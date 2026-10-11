package iec61850

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

// Client is an IEC 61850 client association with one IED (8-1 mapping of
// the ACSI services onto MMS).
type Client struct {
	c *mms.Client

	mu      sync.Mutex
	types   map[string]mms.TypeSpec
	waiters map[string]*ctlWaiter // by control object "LD/LN$CO$DO"
	reports chan mms.InformationReport
	dropped int
	ctlNum  uint8
}

// Connect associates with an IED.
func Connect(ctx context.Context, addr string, o mms.DialOptions) (*Client, error) {
	cl := &Client{types: map[string]mms.TypeSpec{}, waiters: map[string]*ctlWaiter{}, reports: make(chan mms.InformationReport, 4096)}
	o.OnReport = cl.onReport
	c, err := mms.Dial(ctx, addr, o)
	if err != nil {
		return nil, err
	}
	cl.c = c
	return cl, nil
}

// MMS is the underlying MMS association.
func (cl *Client) MMS() *mms.Client { return cl.c }

// Reports delivers report information reports (RPT), in arrival order.
func (cl *Client) Reports() <-chan mms.InformationReport { return cl.reports }

// Close concludes the association (bounded by ctx) and closes it.
func (cl *Client) Close(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_ = cl.c.Conclude(cctx)
	cl.c.Close()
}

func (cl *Client) onReport(r mms.InformationReport) {
	if r.Spec.ListName != nil && r.Spec.ListName.Scope == mms.ScopeVMD && r.Spec.ListName.Item == "RPT" {
		select {
		case cl.reports <- r:
		default:
			cl.mu.Lock()
			cl.dropped++
			cl.mu.Unlock()
		}
		return
	}
	cl.controlReport(r)
}

// TypeOf returns (and caches) a variable's MMS type.
func (cl *Client) TypeOf(ctx context.Context, n mms.ObjectName) (mms.TypeSpec, error) {
	key := n.String()
	cl.mu.Lock()
	t, ok := cl.types[key]
	cl.mu.Unlock()
	if ok {
		return t, nil
	}
	t, err := cl.c.GetVariableAccessAttributes(ctx, n)
	if err != nil {
		return mms.TypeSpec{}, fmt.Errorf("reading the type of %s: %w", key, err)
	}
	cl.mu.Lock()
	cl.types[key] = t
	cl.mu.Unlock()
	return t, nil
}

// LogicalDevices lists the IED's logical devices (MMS domains).
func (cl *Client) LogicalDevices(ctx context.Context) ([]string, error) {
	return cl.c.GetNameList(ctx, mms.ClassDomain, "")
}

// LDModel is a discovered logical device.
type LDModel struct {
	Name string `json:"name"`
	// LogicalNodes maps each logical node to its data objects per
	// functional constraint.
	LogicalNodes map[string]map[string][]string `json:"logicalNodes"`
	// DataSets maps each data set ("LLN0$Meas") to its members.
	DataSets map[string][]string `json:"dataSets,omitempty"`
	// Reports lists report control blocks ("LLN0.BR.brcbMeas01").
	Reports []string `json:"reports,omitempty"`
	// ControlBlocks lists the other control blocks by functional
	// constraint: LG (log), GO (GOOSE), MS (sampled values), RG and RS
	// (routable GOOSE and SV), GS and US (deprecated), and SP for the
	// setting group control block ("LLN0.SP.SGCB").
	ControlBlocks map[string][]string `json:"controlBlocks,omitempty"`
	// Logs are the logical device's logs (MMS journals, "LLN0$GeneralLog").
	Logs []string `json:"logs,omitempty"`
}

// controlBlockFCs are the functional constraints under which a logical
// node holds control blocks rather than data objects (IEC 61850-8-1
// 7.3.1 Figure 4, 12.2).
var controlBlockFCs = map[string]bool{"LG": true, "GO": true, "GS": true, "MS": true, "US": true, "RG": true, "RS": true}

// Discover reads the data model of one logical device
// (GetLogicalDeviceDirectory and GetLogicalNodeDirectory, IEC 61850-8-1
// 11 and 12.3.1: GetNameList of named variables, named variable lists and
// journals): logical nodes and their data objects by functional
// constraint, data sets, report and other control blocks, and logs.
func (cl *Client) Discover(ctx context.Context, ld string) (LDModel, error) {
	m := LDModel{Name: ld, LogicalNodes: map[string]map[string][]string{}}
	names, err := cl.c.GetNameList(ctx, mms.ClassNamedVariable, ld)
	if err != nil {
		return m, err
	}
	for _, n := range names {
		parts := strings.Split(n, "$")
		switch len(parts) {
		case 1:
			if m.LogicalNodes[n] == nil {
				m.LogicalNodes[n] = map[string][]string{}
			}
		case 3:
			if parts[1] == "BR" || parts[1] == "RP" {
				m.Reports = append(m.Reports, strings.Join(parts, "."))
				continue
			}
			if controlBlockFCs[parts[1]] || (parts[1] == "SP" && parts[2] == "SGCB" && parts[0] == "LLN0") {
				if m.ControlBlocks == nil {
					m.ControlBlocks = map[string][]string{}
				}
				m.ControlBlocks[parts[1]] = append(m.ControlBlocks[parts[1]], strings.Join(parts, "."))
				continue
			}
			fcs := m.LogicalNodes[parts[0]]
			if fcs == nil {
				fcs = map[string][]string{}
				m.LogicalNodes[parts[0]] = fcs
			}
			fcs[parts[1]] = append(fcs[parts[1]], parts[2])
		}
	}
	sets, err := cl.c.GetNameList(ctx, mms.ClassNamedVariableList, ld)
	if err != nil {
		var se *mms.ServiceError
		if !errors.As(err, &se) {
			return m, err
		}
	}
	if len(sets) > 0 {
		m.DataSets = map[string][]string{}
	}
	for _, s := range sets {
		members, err := cl.c.GetNamedVariableListAttributes(ctx, mms.DomainName(ld, s))
		if err != nil {
			return m, fmt.Errorf("data set %s/%s: %w", ld, s, err)
		}
		for _, mem := range members {
			m.DataSets[s] = append(m.DataSets[s], mem.String())
		}
	}
	// Logs are MMS journals; an IED without logs may refuse the class.
	if logs, err := cl.c.GetNameList(ctx, mms.ClassJournal, ld); err == nil {
		m.Logs = logs
	} else if se := (*mms.ServiceError)(nil); !errors.As(err, &se) {
		return m, err
	}
	sort.Strings(m.Reports)
	return m, nil
}

// Attribute is a data attribute found by type discovery.
type Attribute struct {
	Ref  Ref
	Type mms.TypeSpec
}

// Attributes lists the leaf data attributes of a logical node, with their
// functional constraints, from its MMS type (GetVariableAccessAttributes).
func (cl *Client) Attributes(ctx context.Context, ld, ln string) ([]Attribute, error) {
	t, err := cl.TypeOf(ctx, mms.DomainName(ld, ln))
	if err != nil {
		return nil, err
	}
	var out []Attribute
	for _, fc := range t.Components {
		for _, do := range fc.Type.Components {
			walkLeaves(Ref{LD: ld, LN: ln, FC: fc.Name, Path: []string{do.Name}}, do.Type, &out)
		}
	}
	return out, nil
}

func walkLeaves(r Ref, t mms.TypeSpec, out *[]Attribute) {
	if t.Kind != mms.KStructure {
		*out = append(*out, Attribute{Ref: r, Type: t})
		return
	}
	for _, c := range t.Components {
		walkLeaves(r.Child(c.Name), c.Type, out)
	}
}

// DataSetMembers returns a data set's members (GetDataSetDirectory,
// IEC 61850-8-1 14.3.5) for "LD/LLN0$Meas", "@Name" or "/Name".
func (cl *Client) DataSetMembers(ctx context.Context, ref string) ([]mms.ObjectName, error) {
	n, err := ParseObjectReference(ref)
	if err != nil {
		return nil, err
	}
	return cl.c.GetNamedVariableListAttributes(ctx, n)
}

// DataSetValues reads a data set's values (GetDataSetValues, IEC 61850-8-1
// 14.3.1: a Read of the variable list name); a member the IED cannot read
// has its error in its result.
func (cl *Client) DataSetValues(ctx context.Context, ref string) ([]mms.AccessResult, error) {
	n, err := ParseObjectReference(ref)
	if err != nil {
		return nil, err
	}
	return cl.c.Read(ctx, mms.VariableSpec{ListName: &n})
}

// DeleteDataSet deletes a data set (DeleteDataSet, 8-1 14.3.4); an IED
// that keeps the set because a control block uses it answers deleted 0.
func (cl *Client) DeleteDataSet(ctx context.Context, ref string) error {
	n, err := ParseObjectReference(ref)
	if err != nil {
		return err
	}
	_, deleted, err := cl.c.DeleteNamedVariableList(ctx, n)
	if err != nil {
		return err
	}
	if deleted == 0 {
		return fmt.Errorf("the IED did not delete data set %s", ref)
	}
	return nil
}

// AllDataValues reads every attribute of a logical node with one
// functional constraint (GetAllDataValues, IEC 61850-8-1 12.3.2, through
// the flattened name LN$FC).
func (cl *Client) AllDataValues(ctx context.Context, ld, ln, fc string) (mms.TypeSpec, mms.Data, error) {
	n := Ref{LD: ld, LN: ln, FC: fc}.MMS()
	t, err := cl.TypeOf(ctx, n)
	if err != nil {
		return t, mms.Data{}, err
	}
	d, err := cl.c.ReadOne(ctx, n)
	return t, d, err
}

// ---- report control blocks ---------------------------------------------------

// Option field bits (8-1 report encoding of OptFlds).
const (
	optSeqNum    = 1
	optTimeStamp = 2
	optReason    = 3
	optDataSet   = 4
	optDataRef   = 5
	optBufOvfl   = 6
	optEntryID   = 7
	optConfRev   = 8
	optSegment   = 9
)

// Trigger option bits (TrgOps) by name.
var triggerBits = map[string]int{"dchg": 1, "qchg": 2, "dupd": 3, "integrity": 4, "gi": 5}

// IsTriggerOption reports whether name is a trigger option of report and
// log control blocks (dchg, qchg, dupd, integrity, gi; IEC 61850-7-2 5.8).
func IsTriggerOption(name string) bool {
	_, ok := triggerBits[name]
	return ok
}

// Reason code bits by position.
var reasonNames = []string{"reserved", "dchg", "qchg", "dupd", "integrity", "gi", "application"}

// RCBOptions configure a report control block before enabling it.
type RCBOptions struct {
	DataSet string // "LD/LLN0$Name" or "@Name"; empty keeps the IED's
	RptID   string // empty keeps the IED's
	TrgOps  []string
	IntgPd  time.Duration
	BufTm   time.Duration
	EntryID []byte // BRCB: resume after this entry
	GI      bool
	Reserve bool // URCB: write Resv first
	// ReserveTime, when positive, reserves a BRCB for this client first
	// (ResvTms in seconds, IEC 61850-7-2 17.2.2.17 and Annex E.2); a block
	// without ResvTms (an edition 1 IED) is used without reserving.
	ReserveTime int
	NoOptFlds   bool // leave OptFlds as configured in the IED
}

// ErrResumeRefused reports that the IED no longer holds the entry to resume
// after (its buffer overflowed); reporting starts from what it has.
var ErrResumeRefused = errors.New("the IED refused to resume after the stored entry")

// ErrReserved reports a report control block another client has reserved
// or enabled: its reservation or its RptEna could not be written
// (IEC 61850-7-2 17.2.2.17, 17.2.4 and Annex E). Another instance of an
// indexed block may be free.
var ErrReserved = errors.New("the report control block is reserved by another client")

// reservedErr turns a refused reservation or enable into ErrReserved.
func reservedErr(err error) error {
	if errors.Is(err, mms.ErrObjectAccessDenied) || errors.Is(err, mms.ErrTemporarilyUnavail) {
		return fmt.Errorf("%w: %v", ErrReserved, err)
	}
	return err
}

// RCBValues reads a report control block (GetBRCBValues or
// GetURCBValues, IEC 61850-8-1 17.2.2: a read of the whole block) and
// returns its attributes by name.
func (cl *Client) RCBValues(ctx context.Context, rcb Ref) (map[string]mms.Data, error) {
	t, err := cl.TypeOf(ctx, rcb.MMS())
	if err != nil {
		return nil, err
	}
	d, err := cl.c.ReadOne(ctx, rcb.MMS())
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", rcb.String(), err)
	}
	if t.Kind != mms.KStructure || d.Kind != mms.KStructure || len(d.Elems) != len(t.Components) {
		return nil, fmt.Errorf("%s is not a report control block", rcb.String())
	}
	out := make(map[string]mms.Data, len(d.Elems))
	for i, c := range t.Components {
		out[c.Name] = d.Elems[i]
	}
	return out, nil
}

func sameData(a, b mms.Data) bool { return string(a.Encode()) == string(b.Encode()) }

// EnableReport configures and enables a report control block (ref like
// "LD/LLN0$BR$brcbMeas01"): reserve (Resv or ResvTms), disable, set what
// differs, resume after EntryID, enable, then general interrogation. Only
// attributes whose value changes are written, since a changed RptID,
// DatSet, BufTm, TrgOps or IntgPd purges a BRCB's buffer (IEC 61850-8-1
// 17.1.2). It returns ErrReserved when another client holds the block and
// ErrResumeRefused (with reporting enabled) when the EntryID could not be
// set.
func (cl *Client) EnableReport(ctx context.Context, rcb Ref, o RCBOptions) error {
	buffered := rcb.FC == "BR"
	cur, err := cl.RCBValues(ctx, rcb)
	if err != nil {
		return err
	}
	w := func(attr string, v mms.Data) error {
		if err := cl.c.WriteOne(ctx, rcb.Child(attr).MMS(), v); err != nil {
			return fmt.Errorf("writing %s of %s: %w", attr, rcb.String(), err)
		}
		cur[attr] = v
		return nil
	}
	set := func(attr string, v mms.Data) error {
		if c, ok := cur[attr]; ok && sameData(c, v) {
			return nil
		}
		return w(attr, v)
	}
	if _, ok := cur["Resv"]; ok && !buffered && o.Reserve {
		if err := w("Resv", mms.Boolean(true)); err != nil {
			return reservedErr(err)
		}
	}
	if _, ok := cur["ResvTms"]; ok && buffered && o.ReserveTime > 0 {
		if err := w("ResvTms", mms.Integer(int64(min(o.ReserveTime, 32767)))); err != nil {
			return reservedErr(err)
		}
	}
	// A block left enabled by an earlier association of ours is disabled
	// first so it can be configured; one enabled by another client
	// refuses.
	if cur["RptEna"].Bool {
		if err := w("RptEna", mms.Boolean(false)); err != nil {
			return reservedErr(err)
		}
	}
	if o.RptID != "" {
		if err := set("RptID", mms.Visible(o.RptID)); err != nil {
			return err
		}
	}
	if o.DataSet != "" {
		if err := set("DatSet", mms.Visible(o.DataSet)); err != nil {
			return err
		}
	}
	if !o.NoOptFlds {
		opt := mms.NewBitString(10)
		if c := cur["OptFlds"]; c.Kind == mms.KBitString && c.Bits.NBits > 10 {
			opt = mms.NewBitString(c.Bits.NBits)
		}
		for _, b := range []int{optSeqNum, optTimeStamp, optReason, optDataSet, optDataRef, optConfRev} {
			opt.Set(b, true)
		}
		if buffered {
			opt.Set(optBufOvfl, true)
			opt.Set(optEntryID, true)
		}
		if err := set("OptFlds", mms.Bits(opt)); err != nil {
			return err
		}
	}
	if len(o.TrgOps) > 0 {
		trg := mms.NewBitString(6)
		if c := cur["TrgOps"]; c.Kind == mms.KBitString && c.Bits.NBits > 6 {
			trg = mms.NewBitString(c.Bits.NBits)
		}
		for _, name := range o.TrgOps {
			b, ok := triggerBits[name]
			if !ok {
				return fmt.Errorf("trigger option %q is not dchg, qchg, dupd, integrity or gi", name)
			}
			trg.Set(b, true)
		}
		if err := set("TrgOps", mms.Bits(trg)); err != nil {
			return err
		}
	}
	if o.IntgPd > 0 {
		if err := set("IntgPd", mms.Unsigned(uint64(o.IntgPd.Milliseconds()))); err != nil {
			return err
		}
	}
	if o.BufTm > 0 {
		if err := set("BufTm", mms.Unsigned(uint64(o.BufTm.Milliseconds()))); err != nil {
			return err
		}
	}
	var resumeErr error
	// The NULL EntryID (all zero) is not a received entry (8-1 8.1.3.5).
	if buffered && len(o.EntryID) > 0 && !allZero(o.EntryID) {
		if err := w("EntryID", mms.Octets(o.EntryID)); err != nil {
			resumeErr = fmt.Errorf("%w: %v", ErrResumeRefused, err)
		}
	}
	if err := w("RptEna", mms.Boolean(true)); err != nil {
		return reservedErr(err)
	}
	if o.GI {
		if err := w("GI", mms.Boolean(true)); err != nil {
			return err
		}
	}
	return resumeErr
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// ReadRCB reads a report control block's RptID and DatSet.
func (cl *Client) ReadRCB(ctx context.Context, rcb Ref) (rptID, dataSet string, err error) {
	res, err := cl.c.Read(ctx, mms.VariableSpec{Vars: []mms.ObjectName{rcb.Child("RptID").MMS(), rcb.Child("DatSet").MMS()}})
	if err != nil {
		return "", "", err
	}
	if len(res) != 2 {
		return "", "", errors.New("the IED answered the wrong number of results")
	}
	for _, r := range res {
		if r.Err != nil {
			return "", "", fmt.Errorf("reading %s: %w", rcb.String(), r.Err)
		}
	}
	return res[0].Data.Str, res[1].Data.Str, nil
}

// ParsedReport is a decoded IEC 61850 report.
type ParsedReport struct {
	RptID       string
	SeqNum      *uint64
	TimeOfEntry time.Time
	DataSet     string
	BufOvfl     bool
	EntryID     []byte
	ConfRev     *uint64
	// Segmented reports carry SubSeqNum and MoreSegmentsFollow; a
	// Reassembler joins the segments into one report.
	Segmented    bool
	SubSeqNum    uint64
	MoreSegments bool
	// Entries are the included members, in data set order.
	Entries []ReportEntry
}

// ReportEntry is one included data set member.
type ReportEntry struct {
	Index   int    // position in the data set
	Ref     string // data reference, when the report carries it
	Value   mms.Data
	Reasons []string
}

// ParseReport decodes an RPT information report (8-1 report format).
func ParseReport(r mms.InformationReport) (ParsedReport, error) {
	res := r.Results
	var rep ParsedReport
	i := 0
	next := func(k mms.Kind, what string) (mms.Data, error) {
		if i >= len(res) {
			return mms.Data{}, fmt.Errorf("the report ends before %s", what)
		}
		d := res[i]
		i++
		if d.Err != nil || d.Data.Kind != k {
			return mms.Data{}, fmt.Errorf("the report's %s is not a %s", what, k)
		}
		return d.Data, nil
	}
	id, err := next(mms.KVisible, "RptID")
	if err != nil {
		return rep, err
	}
	rep.RptID = id.Str
	of, err := next(mms.KBitString, "OptFlds")
	if err != nil {
		return rep, err
	}
	opt := of.Bits
	if opt.Get(optSeqNum) {
		d, err := next(mms.KUint, "SqNum")
		if err != nil {
			return rep, err
		}
		rep.SeqNum = &d.Uint
	}
	if opt.Get(optTimeStamp) {
		d, err := next(mms.KBinaryTime, "TimeOfEntry")
		if err != nil {
			return rep, err
		}
		rep.TimeOfEntry, _ = mms.DecodeBinaryTime(d.Bytes)
	}
	if opt.Get(optDataSet) {
		d, err := next(mms.KVisible, "DatSet")
		if err != nil {
			return rep, err
		}
		rep.DataSet = d.Str
	}
	if opt.Get(optBufOvfl) {
		d, err := next(mms.KBool, "BufOvfl")
		if err != nil {
			return rep, err
		}
		rep.BufOvfl = d.Bool
	}
	if opt.Get(optEntryID) {
		d, err := next(mms.KOctets, "EntryID")
		if err != nil {
			return rep, err
		}
		rep.EntryID = d.Bytes
	}
	if opt.Get(optConfRev) {
		d, err := next(mms.KUint, "ConfRev")
		if err != nil {
			return rep, err
		}
		rep.ConfRev = &d.Uint
	}
	if opt.Get(optSegment) {
		sub, err := next(mms.KUint, "SubSqNum")
		if err != nil {
			return rep, err
		}
		more, err := next(mms.KBool, "MoreSegmentsFollow")
		if err != nil {
			return rep, err
		}
		rep.Segmented, rep.SubSeqNum, rep.MoreSegments = true, sub.Uint, more.Bool
	}
	inc, err := next(mms.KBitString, "Inclusion")
	if err != nil {
		return rep, err
	}
	for k := 0; k < inc.Bits.NBits; k++ {
		if inc.Bits.Get(k) {
			rep.Entries = append(rep.Entries, ReportEntry{Index: k})
		}
	}
	if opt.Get(optDataRef) {
		for k := range rep.Entries {
			d, err := next(mms.KVisible, "data reference")
			if err != nil {
				return rep, err
			}
			rep.Entries[k].Ref = d.Str
		}
	}
	for k := range rep.Entries {
		if i >= len(res) {
			return rep, errors.New("the report ends before its values")
		}
		if res[i].Err != nil {
			return rep, fmt.Errorf("the report's value %d is a failure: %w", k, res[i].Err)
		}
		rep.Entries[k].Value = res[i].Data
		i++
	}
	if opt.Get(optReason) {
		for k := range rep.Entries {
			d, err := next(mms.KBitString, "reason code")
			if err != nil {
				return rep, err
			}
			for b, name := range reasonNames {
				if b > 0 && d.Bits.Get(b) {
					rep.Entries[k].Reasons = append(rep.Entries[k].Reasons, name)
				}
			}
		}
	}
	return rep, nil
}

// Reassembler joins the segments of segmented reports (8-1 report
// format: the segments of one report share RptID and SqNum and count
// SubSqNum up from 0; the last has MoreSegmentsFollow false).
type Reassembler struct {
	pending map[string]*ParsedReport // by RptID
}

// ErrSegmentLost reports a segmented report that could not be completed
// (a segment missing or out of order); its partial content is dropped.
var ErrSegmentLost = errors.New("a segment of a segmented report is missing")

// maxSegmentEntries bounds a reassembled report.
const maxSegmentEntries = 1 << 16

// Add takes a parsed report. It returns the complete report and true for
// an unsegmented report or the last segment of a complete one, and false
// while more segments are due.
func (a *Reassembler) Add(rep ParsedReport) (ParsedReport, bool, error) {
	if !rep.Segmented {
		return rep, true, nil
	}
	if a.pending == nil {
		a.pending = map[string]*ParsedReport{}
	}
	var lost error
	cur := a.pending[rep.RptID]
	switch {
	case rep.SubSeqNum == 0:
		if cur != nil {
			lost = fmt.Errorf("%w: report %s ended before its last segment", ErrSegmentLost, rep.RptID)
		}
		cp := rep
		cp.Entries = append([]ReportEntry(nil), rep.Entries...)
		cur = &cp
	case cur == nil || cur.SubSeqNum+1 != rep.SubSeqNum || !sameSeq(cur.SeqNum, rep.SeqNum) ||
		len(cur.Entries)+len(rep.Entries) > maxSegmentEntries:
		delete(a.pending, rep.RptID)
		return ParsedReport{}, false, fmt.Errorf("%w: report %s segment %d", ErrSegmentLost, rep.RptID, rep.SubSeqNum)
	default:
		cur.SubSeqNum = rep.SubSeqNum
		cur.Entries = append(cur.Entries, rep.Entries...)
		cur.BufOvfl = cur.BufOvfl || rep.BufOvfl
		if len(rep.EntryID) > 0 {
			cur.EntryID = rep.EntryID
		}
	}
	if rep.MoreSegments {
		a.pending[rep.RptID] = cur
		return ParsedReport{}, false, lost
	}
	delete(a.pending, rep.RptID)
	out := *cur
	out.Segmented, out.MoreSegments = false, false
	return out, true, lost
}

func sameSeq(a, b *uint64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// DefineDataSet makes the data set ref hold members (CreateDataSet,
// IEC 61850-8-1 14.3.3: DefineNamedVariableList): "LD/LLN0$Name" is
// persistent (domain-specific), "@Name" non-persistent (association-
// specific, gone when the association ends). rcb, the block that will use
// it, is disabled first so a set left by an earlier association can be
// deleted and defined again; a set that already holds the same members is
// kept.
func (cl *Client) DefineDataSet(ctx context.Context, rcb Ref, ref string, members []mms.ObjectName) error {
	name, err := ParseObjectReference(ref)
	if err != nil {
		return err
	}
	if name.Scope == mms.ScopeVMD {
		return fmt.Errorf("data set %s: a data set is LD/LN$Name or @Name", ref)
	}
	_ = cl.c.WriteOne(ctx, rcb.Child("RptEna").MMS(), mms.Boolean(false))
	have, err := cl.c.GetNamedVariableListAttributes(ctx, name)
	if err == nil && sameNames(have, members) {
		return nil
	}
	if err == nil {
		if _, deleted, err := cl.c.DeleteNamedVariableList(ctx, name); err != nil || deleted == 0 {
			return fmt.Errorf("data set %s exists with other members and could not be deleted", ref)
		}
	}
	if err := cl.c.DefineNamedVariableList(ctx, name, members); err != nil {
		return fmt.Errorf("defining data set %s: %w", ref, err)
	}
	return nil
}

func sameNames(a, b []mms.ObjectName) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].String() != b[i].String() {
			return false
		}
	}
	return true
}
