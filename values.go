package iec61850

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

// Functional constraints that appear as MMS components (IEC 61850-8-1
// 7.3.1, Figure 4): the data FCs of IEC 61850-7-2 Table 4 plus CO and the
// control block FCs (RP, LG, BR, GO, GS, MS, US, RG, RS). The service-only
// wildcard XX is not mapped (8-1 7.3.1 NOTE 2).
var functionalConstraints = map[string]bool{
	"MX": true, "ST": true, "CO": true, "CF": true, "DC": true, "SP": true, "SG": true, "RP": true,
	"LG": true, "BR": true, "GO": true, "GS": true, "SV": true, "SE": true, "MS": true, "US": true,
	"EX": true, "SR": true, "OR": true, "BL": true, "RG": true, "RS": true,
}

// MaxIdentifier is the longest MMS identifier (domain or item name) the
// mapping allows (IEC 61850-8-1 8.1.3.2.2 and F.3.2); MaxObjectReference
// the longest ObjectReference visible string (8.1.3.2).
const (
	MaxIdentifier      = 64
	MaxObjectReference = 129
)

// Ref is an IEC 61850 data reference with its functional constraint:
// LD/LN.DO[.SDO].DA… plus FC, or the MMS form LD/LN$FC$DO$DA.
type Ref struct {
	LD, LN string
	FC     string
	Path   []string // data object, sub-objects and attributes
}

// ParseRef reads "LD/LN.DO.DA" (with fc) or "LD/LN$FC$DO$DA" (fc empty
// or equal).
func ParseRef(s, fc string) (Ref, error) {
	i := strings.IndexByte(s, '/')
	if i <= 0 || i == len(s)-1 {
		return Ref{}, fmt.Errorf("reference %q is not LD/LN.DO…", s)
	}
	r := Ref{LD: s[:i]}
	rest := s[i+1:]
	if strings.Contains(rest, "$") {
		parts := strings.Split(rest, "$")
		r.LN = parts[0]
		if len(parts) > 1 {
			r.FC = parts[1]
			r.Path = parts[2:]
		}
		if fc != "" && fc != r.FC {
			return Ref{}, fmt.Errorf("reference %q has functional constraint %s, not %s", s, r.FC, fc)
		}
	} else {
		parts := strings.Split(rest, ".")
		r.LN, r.Path, r.FC = parts[0], parts[1:], strings.ToUpper(fc)
	}
	if r.LN == "" {
		return Ref{}, fmt.Errorf("reference %q has no logical node", s)
	}
	if r.FC != "" && !functionalConstraints[r.FC] {
		return Ref{}, fmt.Errorf("reference %q: %q is not a functional constraint", s, r.FC)
	}
	for _, p := range r.Path {
		if p == "" {
			return Ref{}, fmt.Errorf("reference %q has an empty name", s)
		}
	}
	if n := r.MMS(); len(n.Domain) > MaxIdentifier || len(n.Item) > MaxIdentifier {
		return Ref{}, fmt.Errorf("reference %q: an MMS name is longer than %d characters", s, MaxIdentifier)
	}
	return r, nil
}

// ParseObjectReference reads the ObjectReference of a control block
// attribute such as DatSet or LogRef (IEC 61850-8-1 8.1.3.2.2):
// "LD/LLN0$Name" (domain-specific), "@Name" (association-specific, a
// non-persistent data set) or "/Name" (VMD-specific). "." is accepted for
// "$" after the logical device.
func ParseObjectReference(s string) (mms.ObjectName, error) {
	if s == "" || len(s) > MaxObjectReference {
		return mms.ObjectName{}, fmt.Errorf("object reference %q is empty or longer than %d characters", s, MaxObjectReference)
	}
	var n mms.ObjectName
	switch {
	case s[0] == '@':
		n = mms.ObjectName{Scope: mms.ScopeAA, Item: s[1:]}
	case s[0] == '/':
		n = mms.VMDName(s[1:])
	default:
		i := strings.IndexByte(s, '/')
		if i <= 0 {
			return mms.ObjectName{}, fmt.Errorf("object reference %q is not LD/Name, @Name or /Name", s)
		}
		n = mms.DomainName(s[:i], s[i+1:])
	}
	n.Item = strings.ReplaceAll(n.Item, ".", "$")
	if n.Item == "" || len(n.Item) > MaxIdentifier || len(n.Domain) > MaxIdentifier || strings.ContainsAny(n.Item, "/@ ") {
		return mms.ObjectName{}, fmt.Errorf("object reference %q does not name an MMS object", s)
	}
	return n, nil
}

// FormatObjectReference is the ObjectReference form of an MMS name
// (IEC 61850-8-1 8.1.3.2.2).
func FormatObjectReference(n mms.ObjectName) string {
	switch n.Scope {
	case mms.ScopeAA:
		return "@" + n.Item
	case mms.ScopeVMD:
		return "/" + n.Item
	}
	return n.Domain + "/" + n.Item
}

// RefFromMMS turns an MMS domain-specific name into a reference.
func RefFromMMS(n mms.ObjectName) Ref {
	r, _ := ParseRef(n.Domain+"/"+n.Item, "")
	return r
}

// MMS is the reference's MMS variable name.
func (r Ref) MMS() mms.ObjectName {
	item := r.LN
	if r.FC != "" {
		item += "$" + r.FC
		for _, p := range r.Path {
			item += "$" + p
		}
	}
	return mms.DomainName(r.LD, item)
}

// String is the dotted form "LD/LN.DO.DA".
func (r Ref) String() string {
	s := r.LD + "/" + r.LN
	for _, p := range r.Path {
		s += "." + p
	}
	return s
}

// Child is the reference of a sub-element.
func (r Ref) Child(names ...string) Ref {
	c := r
	c.Path = append(append([]string(nil), r.Path...), names...)
	return c
}

// Parent is the containing element's reference (the data object of an
// attribute).
func (r Ref) Parent() Ref {
	c := r
	if len(c.Path) > 0 {
		c.Path = c.Path[:len(c.Path)-1]
	}
	return c
}

// ---- quality ---------------------------------------------------------------

// Quality detail bits of the IEC 61850 quality bit string, after the two
// validity bits (IEC 61850-8-1 8.2 Table 44; bit 0 is the most significant
// bit of the first octet, 8.1.3.6).
var qualityDetails = []string{"overflow", "outOfRange", "badReference", "oscillatory", "failure",
	"oldData", "inconsistent", "inaccurate"}

// QualityJSON describes a quality bit string for a reading. Bits the IED
// does not send take their default (8-1 8.2: the string is variable
// length; good, process, false); bits after operatorBlocked are ignored.
func QualityJSON(b mms.BitString) map[string]any {
	validity := "good"
	switch {
	case b.Get(0) && b.Get(1):
		validity = "questionable"
	case b.Get(1):
		validity = "invalid"
	case b.Get(0):
		validity = "reserved"
	}
	var details []any
	for i, n := range qualityDetails {
		if b.Get(2 + i) {
			details = append(details, n)
		}
	}
	src := "process"
	if b.Get(10) {
		src = "substituted"
	}
	out := map[string]any{"validity": validity, "source": src, "test": b.Get(11), "operatorBlocked": b.Get(12)}
	if len(details) > 0 {
		out["details"] = details
	}
	return out
}

// ---- values ------------------------------------------------------------------

// ToJSON converts MMS data to JSON values using its type's component
// names. Quality ("q") and time stamps become objects and RFC 3339 times.
func ToJSON(t *mms.TypeSpec, d mms.Data, name string) any {
	switch d.Kind {
	case mms.KStructure:
		out := map[string]any{}
		for i, e := range d.Elems {
			key := strconv.Itoa(i)
			var ct *mms.TypeSpec
			if t != nil && i < len(t.Components) {
				key = t.Components[i].Name
				ct = &t.Components[i].Type
			}
			out[key] = ToJSON(ct, e, key)
		}
		return out
	case mms.KArray:
		out := make([]any, len(d.Elems))
		for i, e := range d.Elems {
			var et *mms.TypeSpec
			if t != nil {
				et = t.Elem
			}
			out[i] = ToJSON(et, e, "")
		}
		return out
	case mms.KBool:
		return d.Bool
	case mms.KInt:
		return d.Int
	case mms.KUint:
		return d.Uint
	case mms.KFloat:
		if !d.Double {
			// Shortest decimal of the single-precision value.
			f, _ := strconv.ParseFloat(strconv.FormatFloat(d.Float, 'g', -1, 32), 64)
			return f
		}
		if math.IsNaN(d.Float) || math.IsInf(d.Float, 0) {
			return nil
		}
		return d.Float
	case mms.KBitString:
		if name == "q" && d.Bits.NBits >= 2 && d.Bits.NBits <= 16 {
			return QualityJSON(d.Bits)
		}
		if (name == "stVal" || name == "ctlVal") && d.Bits.NBits == 2 {
			return dbpos(d.Bits)
		}
		var sb strings.Builder
		for i := 0; i < d.Bits.NBits; i++ {
			if d.Bits.Get(i) {
				sb.WriteByte('1')
			} else {
				sb.WriteByte('0')
			}
		}
		return sb.String()
	case mms.KOctets:
		return hex.EncodeToString(d.Bytes)
	case mms.KVisible, mms.KMMSString:
		return d.Str
	case mms.KUTCTime:
		if d.Time.T.IsZero() {
			return nil
		}
		return d.Time.T.UTC().Format(time.RFC3339Nano)
	case mms.KBinaryTime:
		t, err := mms.DecodeBinaryTime(d.Bytes)
		if err != nil {
			return nil
		}
		return t.Format(time.RFC3339Nano)
	}
	return nil
}

// TimeQualityJSON describes the TimeQuality octet of a Timestamp
// (IEC 61850-8-1 8.1.3.7 Table 36, IEC 61850-7-2 6.2.3.8): accuracy 31 is
// unspecified and 25 to 30 are invalid.
func TimeQualityJSON(q byte) map[string]any {
	acc := any(int(q & mms.TimeAccuracyMask))
	switch n := int(q & mms.TimeAccuracyMask); {
	case n == 31:
		acc = "unspecified"
	case n > 24:
		acc = "invalid"
	}
	return map[string]any{"leapSecondsKnown": q&mms.TimeLeapSecondKnown != 0, "clockFailure": q&mms.TimeClockFailure != 0,
		"clockNotSynchronized": q&mms.TimeClockNotSynced != 0, "timeAccuracy": acc}
}

// timeTrusted reports whether a time stamp's quality lets the time be
// used as it is: no clock failure and a synchronised clock.
func timeTrusted(q byte) bool { return q&(mms.TimeClockFailure|mms.TimeClockNotSynced) == 0 }

// dbpos names a double point position (DpStatusKind, IEC 61850-7-2
// 6.2.5.3; a coded enum is the bit string of its value, 8-1 8.1.2.3).
func dbpos(b mms.BitString) string {
	switch {
	case b.Get(0) && !b.Get(1):
		return "on"
	case !b.Get(0) && b.Get(1):
		return "off"
	case b.Get(0) && b.Get(1):
		return "bad-state"
	}
	return "intermediate-state"
}

// FromJSON converts a JSON value to MMS data of type t.
func FromJSON(t mms.TypeSpec, v any) (mms.Data, error) {
	switch t.Kind {
	case mms.KBool:
		b, ok := v.(bool)
		if !ok {
			return mms.Data{}, fmt.Errorf("%v is not a boolean", v)
		}
		return mms.Boolean(b), nil
	case mms.KInt:
		n, err := integer(v)
		if err != nil {
			return mms.Data{}, err
		}
		if bits := t.Size; bits > 0 && bits < 64 && (n < -(1<<(bits-1)) || n >= 1<<(bits-1)) {
			return mms.Data{}, fmt.Errorf("%d does not fit a %d-bit integer", n, bits)
		}
		return mms.Integer(n), nil
	case mms.KUint:
		n, err := integer(v)
		if err != nil {
			return mms.Data{}, err
		}
		if n < 0 || (t.Size > 0 && t.Size < 64 && n >= 1<<t.Size) {
			return mms.Data{}, fmt.Errorf("%d does not fit a %d-bit unsigned integer", n, t.Size)
		}
		return mms.Unsigned(uint64(n)), nil
	case mms.KFloat:
		f, ok := v.(float64)
		if !ok {
			return mms.Data{}, fmt.Errorf("%v is not a number", v)
		}
		if t.Size == 64 {
			return mms.Float64(f), nil
		}
		return mms.Float32(f), nil
	case mms.KVisible, mms.KMMSString:
		s, ok := v.(string)
		if !ok {
			return mms.Data{}, fmt.Errorf("%v is not a string", v)
		}
		if t.Size != 0 && len(s) > abs(t.Size) {
			return mms.Data{}, fmt.Errorf("the string is longer than %d characters", abs(t.Size))
		}
		return mms.Data{Kind: t.Kind, Str: s}, nil
	case mms.KOctets:
		s, ok := v.(string)
		if !ok {
			return mms.Data{}, fmt.Errorf("%v is not a hexadecimal string", v)
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return mms.Data{}, fmt.Errorf("%q is not hexadecimal", s)
		}
		return mms.Octets(b), nil
	case mms.KBitString:
		n := abs(t.Size)
		bs := mms.NewBitString(n)
		switch x := v.(type) {
		case string:
			if v, ok := codedEnum2[x]; ok && n == 2 { // double point or step command
				bs.Set(0, v&2 != 0)
				bs.Set(1, v&1 != 0)
				break
			}
			if len(x) != n {
				return mms.Data{}, fmt.Errorf("%q is not %d bits", x, n)
			}
			for i, c := range x {
				if c != '0' && c != '1' {
					return mms.Data{}, fmt.Errorf("%q is not a string of 0 and 1", x)
				}
				bs.Set(i, c == '1')
			}
		case bool:
			if n != 2 {
				return mms.Data{}, errors.New("a boolean only sets a two-bit position")
			}
			bs.Set(0, x)
			bs.Set(1, !x)
		default:
			return mms.Data{}, fmt.Errorf("%v is not a bit string", v)
		}
		return mms.Bits(bs), nil
	case mms.KUTCTime:
		s, ok := v.(string)
		if !ok {
			return mms.Data{}, fmt.Errorf("%v is not an RFC 3339 time", v)
		}
		tm, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return mms.Data{}, fmt.Errorf("%q is not an RFC 3339 time", s)
		}
		return mms.Timestamp(tm), nil
	case mms.KStructure:
		m, ok := v.(map[string]any)
		if !ok {
			return mms.Data{}, fmt.Errorf("%v is not an object", v)
		}
		out := mms.Structure()
		for _, c := range t.Components {
			cv, ok := m[c.Name]
			if !ok {
				return mms.Data{}, fmt.Errorf("member %s is missing", c.Name)
			}
			d, err := FromJSON(c.Type, cv)
			if err != nil {
				return mms.Data{}, fmt.Errorf("%s: %w", c.Name, err)
			}
			out.Elems = append(out.Elems, d)
		}
		return out, nil
	case mms.KArray:
		a, ok := v.([]any)
		if !ok || t.Elem == nil {
			return mms.Data{}, fmt.Errorf("%v is not an array", v)
		}
		out := mms.Array()
		for i, x := range a {
			d, err := FromJSON(*t.Elem, x)
			if err != nil {
				return mms.Data{}, fmt.Errorf("[%d]: %w", i, err)
			}
			out.Elems = append(out.Elems, d)
		}
		return out, nil
	}
	return mms.Data{}, fmt.Errorf("values of type %s cannot be written", t.Kind)
}

// codedEnum2 are the values of the two-bit coded enumerations of
// IEC 61850-7-2 6.2.5 (DpStatusKind, StepControlKind) by name.
var codedEnum2 = map[string]int{
	"intermediate-state": 0, "off": 1, "on": 2, "bad-state": 3, // DpStatusKind
	"stop": 0, "lower": 1, "higher": 2, // StepControlKind
}

func integer(v any) (int64, error) {
	f, ok := v.(float64)
	if !ok {
		if n, ok := v.(int); ok {
			return int64(n), nil
		}
		return 0, fmt.Errorf("%v is not a number", v)
	}
	if f != math.Trunc(f) || math.Abs(f) > 1<<62 {
		return 0, fmt.Errorf("%v is not an integer", f)
	}
	return int64(f), nil
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// primaryNames are the attributes that carry a data object's value, in the
// order they are looked for (common data classes of IEC 61850-7-3).
var primaryNames = [][]string{
	{"stVal"}, {"mag", "f"}, {"mag", "i"}, {"cVal", "mag", "f"}, {"cVal", "mag", "i"},
	{"instMag", "f"}, {"instMag", "i"}, {"setVal"}, {"setMag", "f"}, {"setMag", "i"},
	{"general"}, {"actVal"}, {"valWTr", "posVal"}, {"ctlVal"},
}

// Sample is a data object or attribute split into value, quality and time.
type Sample struct {
	Value   any
	Quality map[string]any // nil when the element has no quality
	Time    time.Time      // zero when it has no time stamp
	// TimeQuality is the time stamp's quality octet (valid when Time is
	// set or the stamp was all zero).
	TimeQuality byte
	hasTime     bool
	// Attr names the attribute the value came from ("mag.f").
	Attr string
}

// Split extracts the value, quality and time stamp of a data object (a
// structure with component names) or passes an attribute through.
func Split(t *mms.TypeSpec, d mms.Data, name string) Sample {
	if d.Kind != mms.KStructure || t == nil || t.Kind != mms.KStructure {
		return Sample{Value: ToJSON(t, d, name)}
	}
	var s Sample
	if qt, i, ok := t.Find("q"); ok && i < len(d.Elems) && qt.Kind == mms.KBitString {
		s.Quality = QualityJSON(d.Elems[i].Bits)
	}
	if _, i, ok := t.Find("t"); ok && i < len(d.Elems) && d.Elems[i].Kind == mms.KUTCTime {
		s.Time, s.TimeQuality, s.hasTime = d.Elems[i].Time.T, d.Elems[i].Time.Quality, true
	}
	// An untrustworthy time stamp (clock failure or not synchronised) is
	// reported with the quality (IEC 61850-7-2 6.2.3.8).
	if s.hasTime && s.Quality != nil && !timeTrusted(s.TimeQuality) {
		s.Quality["timeQuality"] = TimeQualityJSON(s.TimeQuality)
	}
	for _, path := range primaryNames {
		ct, cd, ok := t, d, true
		for _, p := range path {
			nt, i, found := ct.Find(p)
			if !found || i >= len(cd.Elems) {
				ok = false
				break
			}
			ct, cd = &nt, cd.Elems[i]
		}
		if ok {
			s.Value, s.Attr = ToJSON(ct, cd, path[len(path)-1]), strings.Join(path, ".")
			return s
		}
	}
	// No known value attribute: the whole object without q and t.
	m, _ := ToJSON(t, d, name).(map[string]any)
	delete(m, "q")
	delete(m, "t")
	s.Value = m
	return s
}
