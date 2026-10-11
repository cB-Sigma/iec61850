package tase2

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

// Object names of IEC 60870-6-503:2014 clause 8.3 (and 6.15, G.3). Names
// are facts; the descriptions are ours.
const (
	// VMD scope (8.3.2, 8.3.4).
	VarFeatures = "Supported_Features" // SupportedFeatures bit string
	// VarVersion is the name deployed servers use for TASE.2_Version:
	// the name in 8.3.4 contains a dot, which is not an MMS identifier
	// character (findings F-513). Clients read this name, then the
	// dotted one.
	VarVersion       = "TASE2_Version"
	VarVersionDotted = "TASE.2_Version"
	// Domain (ICC) scope (8.3.3, 8.3.7 to 8.3.13).
	VarBilateralTable = "Bilateral_Table_ID"
	VarNextDSTransfer = "Next_DSTransfer_Set"
	VarTSName         = "Transfer_Set_Name"
	VarTSTimeStamp    = "Transfer_Set_Time_Stamp"
	VarDSConditions   = "DSConditions_Detected"
	VarEventCode      = "Event_Code_Detected"
	VarReportACK      = "Transfer_Report_ACK"
	VarReportNACK     = "Transfer_Report_NACK"
	// Association (AA) scope (8.3.9): the information message transfer
	// set, a Boolean.
	VarIMTransferSet = "IM_Transfer_Set"
	// Information message variables (8.5): the header and the buffer
	// Info_Buff_<octets>.
	VarInfoHeader    = "Info_Mess_Header"
	InfoBufferPrefix = "Info_Buff_"
	// Device variables (6.15): <device>_SBO is the CheckBackID read to
	// select, <device>_TAG the Tag_Value.
	SuffixSelect = "_SBO"
	SuffixTag    = "_TAG"
)

// IsSpecial reports whether an item name is one of the special transfer
// objects a data set may hold (503 7.2.4.2.3).
func IsSpecial(item string) bool {
	switch item {
	case VarTSName, VarTSTimeStamp, VarDSConditions, VarEventCode:
		return true
	}
	return false
}

// DSConditions bits (IEC 60870-6-802 DSConditions).
const (
	CondInterval  = 0 // interval timeout
	CondIntegrity = 1 // integrity timeout
	CondChange    = 2 // object change
	CondOperator  = 3 // operator request
	CondExternal  = 4 // other external event
)

var conditionNames = map[string]int{"interval": CondInterval, "integrity": CondIntegrity, "change": CondChange,
	"operator": CondOperator, "external": CondExternal}

// Conditions builds a DSConditions bit string.
func Conditions(bits ...int) mms.BitString {
	b := mms.NewBitString(5)
	for _, i := range bits {
		b.Set(i, true)
	}
	return b
}

// ConditionBit is the DSConditions bit of a condition name (interval,
// integrity, change, operator, external).
func ConditionBit(name string) (int, bool) {
	b, ok := conditionNames[name]
	return b, ok
}

// ConditionNames lists the set bits of a DSConditions bit string.
func ConditionNames(b mms.BitString) []string {
	var out []string
	for _, n := range []string{"interval", "integrity", "change", "operator", "external"} {
		if b.Get(conditionNames[n]) {
			out = append(out, n)
		}
	}
	return out
}

// Type is an indication point type of IEC 60870-6-802 (Data_Real,
// Data_RealQ, Data_StateQTimeTag …), named without the "Data_" prefix and
// with a lower-case first letter.
type Type string

// field kinds of a point type's structure.
const (
	fValue       = iota // Real (float) or Discrete (integer)
	fState              // Data_State bit string: state in bits 0-1 plus flags
	fFlags              // Data_Flags bit string
	fTime               // GMTBasedS
	fTimeExt            // {GMTBasedS, Milliseconds}
	fCOV                // change-of-value counter
	fSupp               // Data_StateSupplemental bit string: state, tag, expected state
	fSingleFlags        // SingleFlags of a SingleProtectionEvent
	fEventFlags         // EventFlags of a PackedProtectionEvent
	fPackedFlags        // PackedFlags of a PackedProtectionEvent
	fOpTime             // TimeIntervalL16, milliseconds
)

type layout struct {
	base   string // real, state, discrete, flags
	fields []int
}

var types = map[Type]layout{
	"real":                     {"real", []int{fValue}},
	"state":                    {"state", []int{fState}},
	"discrete":                 {"discrete", []int{fValue}},
	"flags":                    {"flags", []int{fFlags}},
	"realQ":                    {"real", []int{fValue, fFlags}},
	"stateQ":                   {"state", []int{fState, fFlags}},
	"discreteQ":                {"discrete", []int{fValue, fFlags}},
	"realQTimeTag":             {"real", []int{fValue, fTime, fFlags}},
	"stateQTimeTag":            {"state", []int{fTime, fState}},
	"discreteQTimeTag":         {"discrete", []int{fValue, fTime, fFlags}},
	"realExtended":             {"real", []int{fValue, fTime, fFlags, fCOV}},
	"stateExtended":            {"state", []int{fTime, fState, fCOV}},
	"discreteExtended":         {"discrete", []int{fValue, fTime, fFlags, fCOV}},
	"realQTimeTagExtended":     {"real", []int{fValue, fTimeExt, fFlags}},
	"stateQTimeTagExtended":    {"state", []int{fTimeExt, fState}},
	"discreteQTimeTagExtended": {"discrete", []int{fValue, fTimeExt, fFlags}},

	"stateSupplemental":                 {"stateSupplemental", []int{fSupp}},
	"stateSupplementalQ":                {"stateSupplemental", []int{fSupp, fFlags}},
	"stateSupplementalQTimeTag":         {"stateSupplemental", []int{fSupp, fTime, fFlags}},
	"stateSupplementalExtended":         {"stateSupplemental", []int{fSupp, fTime, fFlags, fCOV}},
	"stateSupplementalQTimeTagExtended": {"stateSupplemental", []int{fSupp, fTimeExt, fFlags}},

	// Protection equipment events (clause 6.2.3), reported by exception.
	"singleProtectionEvent": {"singleProtection", []int{fSingleFlags, fOpTime, fTimeExt}},
	"packedProtectionEvent": {"packedProtection", []int{fEventFlags, fPackedFlags, fOpTime, fTimeExt}},
}

// Valid reports whether t is a known point type.
func (t Type) Valid() bool { _, ok := types[t]; return ok }

// fieldNames are the component names of the point type structures (our
// reading of IEC 60870-6-802:2014 clause 6, for alternate access by
// component name; findings F-880).
var fieldNames = map[int]string{fValue: "Value", fState: "Value", fFlags: "Flags", fTime: "TimeStamp", fTimeExt: "TimeStamp",
	fCOV: "COV", fSupp: "Value", fSingleFlags: "SingleFlags", fEventFlags: "EventFlags", fPackedFlags: "PackedFlags",
	fOpTime: "OperatingTime"}

// TypeSpecOf is the MMS type description of a point type with named
// components, derived from its value (Encode) for the sizes.
func TypeSpecOf(t Type, v mms.Data) (mms.TypeSpec, bool) {
	l, ok := types[t]
	if !ok {
		return mms.TypeSpec{}, false
	}
	ts := mms.TypeOf(v)
	if len(l.fields) == 1 || v.Kind != mms.KStructure || len(v.Elems) != len(l.fields) {
		return ts, true
	}
	ts.Components = make([]mms.Component, len(l.fields))
	for i, f := range l.fields {
		ts.Components[i] = mms.Component{Name: fieldNames[f], Type: mms.TypeOf(v.Elems[i])}
	}
	return ts, true
}

// Validity codes of the flags.
const (
	Valid    = 0
	Held     = 1
	Suspect  = 2
	NotValid = 3
)

// Current source codes of the flags.
const (
	Telemetered = 0
	Calculated  = 1
	Entered     = 2
	Estimated   = 3
)

// State codes of Data_State.
const (
	StateBetween = 0
	StateTripped = 1 // off / open
	StateClosed  = 2 // on / closed
	StateInvalid = 3
)

// Flags are the quality flags of a data value (IEC 60870-6-802:2014 6.2.1,
// 7.1.1). In the 8-bit Data_Flags and Data_State bit strings (bit 0 the
// first), bits 0-1 are the state (Data_State; unused in Data_Flags), bits
// 2-3 the validity, 4-5 the current source, 6 the normal-value flag (set
// when the value is abnormal) and 7 the time stamp quality (set when the
// time stamp is not valid). Two-bit fields are high bit first.
type Flags struct {
	Validity    int
	Source      int
	Abnormal    bool
	TimeInvalid bool
}

func (f Flags) bits(state int) mms.BitString {
	b := mms.NewBitString(8)
	b.Set(0, state&2 != 0)
	b.Set(1, state&1 != 0)
	b.Set(2, f.Validity&2 != 0)
	b.Set(3, f.Validity&1 != 0)
	b.Set(4, f.Source&2 != 0)
	b.Set(5, f.Source&1 != 0)
	b.Set(6, f.Abnormal)
	b.Set(7, f.TimeInvalid)
	return b
}

func setTwo(b mms.BitString, i, v int) {
	b.Set(i, v&2 != 0)
	b.Set(i+1, v&1 != 0)
}

func (p Protection) bits(kind int) mms.BitString {
	b := mms.NewBitString(8)
	if kind == fEventFlags {
		for i, on := range []bool{p.General, p.Phase1, p.Phase2, p.Phase3, p.Earth, p.Reverse} {
			b.Set(i, on)
		}
		return b
	}
	for i, on := range []bool{p.ElapsedTimeInvalid, p.Blocked, p.Substituted, p.NotTopical, p.EventInvalid} {
		b.Set(i, on)
	}
	if kind == fSingleFlags {
		setTwo(b, 6, p.State)
	}
	return b
}

func (p *Protection) fromBits(kind int, b mms.BitString) {
	if kind == fEventFlags {
		p.General, p.Phase1, p.Phase2, p.Phase3, p.Earth, p.Reverse = b.Get(0), b.Get(1), b.Get(2), b.Get(3), b.Get(4), b.Get(5)
		return
	}
	p.ElapsedTimeInvalid, p.Blocked, p.Substituted, p.NotTopical, p.EventInvalid = b.Get(0), b.Get(1), b.Get(2), b.Get(3), b.Get(4)
	if kind == fSingleFlags {
		p.State = two(b, 6)
	}
}

func two(b mms.BitString, i int) int {
	v := 0
	if b.Get(i) {
		v |= 2
	}
	if b.Get(i + 1) {
		v |= 1
	}
	return v
}

func flagsOf(b mms.BitString) (Flags, int) {
	return Flags{Validity: two(b, 2), Source: two(b, 4), Abnormal: b.Get(6), TimeInvalid: b.Get(7)}, two(b, 0)
}

// Quality is the reading quality: "good", or the flags that are not
// nominal, comma-separated.
func (f Flags) Quality() string {
	var q []string
	switch f.Validity {
	case Held:
		q = append(q, "held")
	case Suspect:
		q = append(q, "suspect")
	case NotValid:
		q = append(q, "invalid")
	}
	switch f.Source {
	case Calculated:
		q = append(q, "calculated")
	case Entered:
		q = append(q, "entered")
	case Estimated:
		q = append(q, "estimated")
	}
	if f.Abnormal {
		q = append(q, "abnormal")
	}
	if f.TimeInvalid {
		q = append(q, "time-invalid")
	}
	if len(q) == 0 {
		return "good"
	}
	return strings.Join(q, ",")
}

// Value is a decoded indication point value.
type Value struct {
	Real     float64
	Discrete int64
	State    int
	Flags    Flags
	HasFlags bool
	Time     time.Time
	COV      int
	// Tag and ExpectedState of a Data_StateSupplemental (tag codes as
	// TagNone …; the expected state coded like State).
	Tag           int
	ExpectedState int
	// Protection is set for protection event types.
	Protection *Protection
}

// Protection is a protection equipment event (IEC 60870-6-802 5.2.4,
// 6.2.3, 7.1.3). Flags: a set flag is the non-nominal value (elapsed time
// invalid, blocked, substituted, not topical, event invalid).
type Protection struct {
	ElapsedTimeInvalid bool
	Blocked            bool
	Substituted        bool
	NotTopical         bool
	EventInvalid       bool
	// State of a single event: 1 off, 2 on, 0 and 3 invalid.
	State int
	// Packed event flags: general, phase 1-3, earth, reverse (start or
	// trip, as the variable's name implies).
	General, Phase1, Phase2, Phase3, Earth, Reverse bool
	// OperatingTime is the event duration (single), duration time (packed
	// start) or operating time (packed trip).
	OperatingTime time.Duration
}

// Quality of a protection event: "good" or its non-nominal flags.
func (p Protection) Quality() string {
	var q []string
	for _, f := range []struct {
		on   bool
		name string
	}{{p.ElapsedTimeInvalid, "elapsed-time-invalid"}, {p.Blocked, "blocked"}, {p.Substituted, "substituted"},
		{p.NotTopical, "not-topical"}, {p.EventInvalid, "invalid"}} {
		if f.on {
			q = append(q, f.name)
		}
	}
	if len(q) == 0 {
		return "good"
	}
	return strings.Join(q, ",")
}

// Quality is the reading quality of a decoded value.
func (v Value) Quality() string {
	if v.Protection != nil {
		return v.Protection.Quality()
	}
	return v.Flags.Quality()
}

// JSON is the reading value: the real or discrete value, or the state code
// (0 between, 1 tripped/off, 2 closed/on, 3 invalid); a supplemental state
// is {state, tag, expectedState}, a protection event an object of its
// state or phase flags and operating time.
func (v Value) JSON(t Type) any {
	switch types[t].base {
	case "real":
		return v.Real
	case "discrete":
		return v.Discrete
	case "state":
		return v.State
	case "stateSupplemental":
		return map[string]any{"state": v.State, "tag": TagName(v.Tag), "expectedState": v.ExpectedState}
	case "singleProtection":
		p := v.Protection
		st := "invalid"
		switch p.State {
		case 1:
			st = "off"
		case 2:
			st = "on"
		}
		return map[string]any{"state": st, "durationMs": p.OperatingTime.Milliseconds()}
	case "packedProtection":
		p := v.Protection
		return map[string]any{"general": p.General, "phase1": p.Phase1, "phase2": p.Phase2, "phase3": p.Phase3,
			"earth": p.Earth, "reverse": p.Reverse, "operatingTimeMs": p.OperatingTime.Milliseconds()}
	}
	return v.Flags.Quality()
}

// Encode builds the MMS data of a value of type t (for simulators and
// tests).
func Encode(t Type, v Value) (mms.Data, error) {
	l, ok := types[t]
	if !ok {
		return mms.Data{}, fmt.Errorf("unknown point type %q", t)
	}
	var out []mms.Data
	for _, f := range l.fields {
		switch f {
		case fValue:
			if l.base == "real" {
				out = append(out, mms.Float32(v.Real))
			} else {
				out = append(out, mms.Integer(v.Discrete))
			}
		case fState:
			out = append(out, mms.Bits(v.Flags.bits(v.State)))
		case fFlags:
			out = append(out, mms.Bits(v.Flags.bits(0)))
		case fTime:
			out = append(out, mms.Integer(gmtSeconds(v.Time)))
		case fTimeExt:
			out = append(out, mms.Structure(mms.Integer(gmtSeconds(v.Time)), mms.Integer(int64(v.Time.Nanosecond()/1e6))))
		case fCOV:
			out = append(out, mms.Unsigned(uint64(uint16(v.COV))))
		case fSupp:
			b := mms.NewBitString(8)
			setTwo(b, 0, v.State)
			setTwo(b, 2, v.Tag)
			setTwo(b, 4, v.ExpectedState)
			out = append(out, mms.Bits(b))
		case fSingleFlags, fEventFlags, fPackedFlags:
			p := v.Protection
			if p == nil {
				p = &Protection{}
			}
			out = append(out, mms.Bits(p.bits(f)))
		case fOpTime:
			var ms int64
			if v.Protection != nil {
				ms = v.Protection.OperatingTime.Milliseconds()
			}
			out = append(out, mms.Integer(ms))
		}
	}
	if len(out) == 1 {
		return out[0], nil
	}
	return mms.Structure(out...), nil
}

// gmtSeconds is GMTBasedS; a zero time is sent as 0 (no time).
func gmtSeconds(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// Decode reads the MMS data of a value of type t.
func Decode(t Type, d mms.Data) (Value, error) {
	l, ok := types[t]
	if !ok {
		return Value{}, fmt.Errorf("unknown point type %q", t)
	}
	if t == "stateQ" && d.Kind == mms.KBitString {
		// Before the 2014 edition Data_StateQ was the Data_State bit
		// string alone; peers still send it (findings F-500).
		l = types["state"]
	}
	parts := []mms.Data{d}
	if len(l.fields) > 1 {
		if d.Kind != mms.KStructure || len(d.Elems) != len(l.fields) {
			return Value{}, fmt.Errorf("a %s is a structure of %d components, got %s", t, len(l.fields), shape(d))
		}
		parts = d.Elems
	}
	var v Value
	for i, f := range l.fields {
		p := parts[i]
		switch f {
		case fValue:
			switch p.Kind {
			case mms.KFloat:
				v.Real, v.Discrete = p.Float, int64(p.Float)
			case mms.KInt:
				v.Real, v.Discrete = float64(p.Int), p.Int
			case mms.KUint:
				v.Real, v.Discrete = float64(p.Uint), int64(p.Uint)
			default:
				return Value{}, fmt.Errorf("a %s value is a number, got %s", t, p.Kind)
			}
		case fState, fFlags:
			if p.Kind != mms.KBitString {
				return Value{}, fmt.Errorf("%s flags are a bit string, got %s", t, p.Kind)
			}
			var st int
			v.Flags, st = flagsOf(p.Bits)
			v.HasFlags = true
			if f == fState {
				v.State = st
			}
		case fTime:
			tm, err := timeOf(p)
			if err != nil {
				return Value{}, err
			}
			v.Time = tm
		case fTimeExt:
			if p.Kind != mms.KStructure || len(p.Elems) != 2 {
				return Value{}, errors.New("an extended time stamp is {seconds, milliseconds}")
			}
			tm, err := timeOf(p.Elems[0])
			if err != nil {
				return Value{}, err
			}
			ms := p.Elems[1].Int
			if p.Elems[1].Kind == mms.KUint {
				ms = int64(p.Elems[1].Uint)
			}
			v.Time = tm.Add(time.Duration(ms) * time.Millisecond)
		case fCOV:
			switch p.Kind {
			case mms.KUint:
				v.COV = int(p.Uint)
			case mms.KInt:
				v.COV = int(p.Int)
			default:
				return Value{}, errors.New("a change-of-value counter is an integer")
			}
		case fSupp:
			if p.Kind != mms.KBitString {
				return Value{}, fmt.Errorf("a %s state is a bit string, got %s", t, p.Kind)
			}
			v.State, v.Tag, v.ExpectedState = two(p.Bits, 0), two(p.Bits, 2), two(p.Bits, 4)
		case fSingleFlags, fEventFlags, fPackedFlags:
			if p.Kind != mms.KBitString {
				return Value{}, fmt.Errorf("%s flags are a bit string, got %s", t, p.Kind)
			}
			if v.Protection == nil {
				v.Protection = &Protection{}
			}
			v.Protection.fromBits(f, p.Bits)
			v.HasFlags = true
		case fOpTime:
			ms := p.Int
			switch p.Kind {
			case mms.KInt:
			case mms.KUint:
				ms = int64(p.Uint)
			default:
				return Value{}, errors.New("an operating time is an integer of milliseconds")
			}
			v.Protection.OperatingTime = time.Duration(ms) * time.Millisecond
		}
	}
	// A state type has no separate flags in single-field form but its bit
	// string carries them.
	return v, nil
}

// TimeOf reads GMTBasedS (seconds since 1970 UTC), tolerating servers that
// send an MMS utc-time instead.
func TimeOf(p mms.Data) (time.Time, error) { return timeOf(p) }

func timeOf(p mms.Data) (time.Time, error) {
	switch p.Kind {
	case mms.KInt:
		if p.Int == 0 {
			return time.Time{}, nil
		}
		return time.Unix(p.Int, 0).UTC(), nil
	case mms.KUint:
		return time.Unix(int64(p.Uint), 0).UTC(), nil
	case mms.KUTCTime:
		return p.Time.T, nil
	}
	return time.Time{}, fmt.Errorf("a time stamp is GMTBasedS seconds, got %s", p.Kind)
}

func shape(d mms.Data) string {
	if d.Kind == mms.KStructure {
		return fmt.Sprintf("a structure of %d", len(d.Elems))
	}
	return d.Kind.String()
}

// ObjectNameData is the "MMS ObjectName" structure of IEC 60870-6-503
// 8.2.3: {Scope Unsigned8 (0 VMD, 1 domain), DomainName, Name}. A VMD
// name carries the placeholder domain "VMD", since the component must be
// 1 to 32 characters and is ignored.
func ObjectNameData(n mms.ObjectName) mms.Data {
	scope, dom := uint64(0), "VMD"
	if n.Scope == mms.ScopeDomain {
		scope, dom = 1, n.Domain
	}
	return mms.Structure(mms.Unsigned(scope), mms.Visible(dom), mms.Visible(n.Item))
}

// ErrNameInconsistent is the 8.2.3 check failing: a name or domain that
// is not an MMS identifier (the server answers
// OBJECT-ATTRIBUTE-INCONSISTENT).
var ErrNameInconsistent = errors.New("not an MMS identifier")

// ObjectNameFrom reads the object name structure (an integer scope is
// also accepted) and checks the identifiers.
func ObjectNameFrom(d mms.Data) (mms.ObjectName, error) {
	if d.Kind != mms.KStructure || len(d.Elems) != 3 {
		return mms.ObjectName{}, errors.New("an object name is {scope, domain, name}")
	}
	var scope int64
	switch e := d.Elems[0]; e.Kind {
	case mms.KUint:
		scope = int64(e.Uint)
	case mms.KInt:
		scope = e.Int
	default:
		return mms.ObjectName{}, fmt.Errorf("an object name scope is Unsigned8, got %s", e.Kind)
	}
	if !MMSIdentifier(d.Elems[2].Str) {
		return mms.ObjectName{}, fmt.Errorf("object name %q: %w", d.Elems[2].Str, ErrNameInconsistent)
	}
	switch scope {
	case 1:
		if !MMSIdentifier(d.Elems[1].Str) {
			return mms.ObjectName{}, fmt.Errorf("domain %q: %w", d.Elems[1].Str, ErrNameInconsistent)
		}
		return mms.DomainName(d.Elems[1].Str, d.Elems[2].Str), nil
	case 0:
		return mms.VMDName(d.Elems[2].Str), nil
	}
	return mms.ObjectName{}, fmt.Errorf("object name scope %d is not 0 (VMD) or 1 (domain)", scope)
}

// MMSIdentifier reports whether s is an MMS identifier as 503 8.2.3
// restricts it: 1 to 32 characters of A-Z, a-z, 0-9, $ and _, not
// starting with a digit.
func MMSIdentifier(s string) bool {
	if s == "" || len(s) > 32 || s[0] >= '0' && s[0] <= '9' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$') {
			return false
		}
	}
	return true
}

// TransferSet is a DSTransferSet value (IEC 60870-6-503 8.2.7.1,
// 6.9.2): the data set, the DSTransmissionPars, the status and the event
// code requested, in this component order.
type TransferSet struct {
	DataSet            mms.ObjectName
	StartTime          time.Time     // GMTBasedS; zero starts at once
	Interval           time.Duration // TimeIntervalS
	TLE                time.Duration // time limit for execution, TimeIntervalS; 0 ignored
	BufferTime         time.Duration // TimeIntervalS; 0 reports each change
	IntegrityCheck     time.Duration // TimeIntervalS
	Conditions         mms.BitString // DSConditions requested
	BlockData          bool
	Critical           bool
	RBE                bool
	AllChangesReported bool
	Status             bool // enabled
	EventCodeRequested int  // Integer16
}

func secs(d time.Duration) mms.Data { return mms.Integer(int64(d / time.Second)) }

// Data encodes the DSTransferSet structure.
func (ts TransferSet) Data() mms.Data {
	cond := ts.Conditions
	if cond.NBits == 0 {
		cond = Conditions()
	}
	return mms.Structure(ObjectNameData(ts.DataSet), mms.Integer(GMTBasedS(ts.StartTime)), secs(ts.Interval), secs(ts.TLE),
		secs(ts.BufferTime), secs(ts.IntegrityCheck), mms.Bits(cond), mms.Boolean(ts.BlockData),
		mms.Boolean(ts.Critical), mms.Boolean(ts.RBE), mms.Boolean(ts.AllChangesReported),
		mms.Boolean(ts.Status), mms.Integer(int64(ts.EventCodeRequested)))
}

func intOf(d mms.Data) (int64, bool) {
	switch d.Kind {
	case mms.KInt:
		return d.Int, true
	case mms.KUint:
		return int64(d.Uint), true
	}
	return 0, false
}

// TransferSetFrom decodes a DSTransferSet, checking every component's
// type and range (negative times and intervals, and event codes outside
// Integer16, are inconsistent).
func TransferSetFrom(d mms.Data) (TransferSet, error) {
	if d.Kind != mms.KStructure || len(d.Elems) != 13 {
		return TransferSet{}, fmt.Errorf("a DSTransferSet is a structure of 13 components, got %s", shape(d))
	}
	e := d.Elems
	name, err := ObjectNameFrom(e[0])
	if err != nil {
		return TransferSet{}, fmt.Errorf("DataSetName: %w", err)
	}
	var n [6]int64
	for i := 1; i <= 5; i++ {
		v, ok := intOf(e[i])
		if !ok || v < 0 || v > 1<<31-1 {
			return TransferSet{}, fmt.Errorf("DSTransferSet component %d is not a non-negative 32-bit integer", i+1)
		}
		n[i] = v
	}
	if e[6].Kind != mms.KBitString {
		return TransferSet{}, errors.New("DSConditionsRequested is a bit string")
	}
	for i := 7; i <= 11; i++ {
		if e[i].Kind != mms.KBool {
			return TransferSet{}, fmt.Errorf("DSTransferSet component %d is a Boolean", i+1)
		}
	}
	ec, ok := intOf(e[12])
	if !ok || ec < -32768 || ec > 32767 {
		return TransferSet{}, errors.New("EventCodeRequested is an Integer16")
	}
	sec := func(v int64) time.Duration { return time.Duration(v) * time.Second }
	ts := TransferSet{DataSet: name, Interval: sec(n[2]), TLE: sec(n[3]), BufferTime: sec(n[4]),
		IntegrityCheck: sec(n[5]), Conditions: e[6].Bits, BlockData: e[7].Bool, Critical: e[8].Bool,
		RBE: e[9].Bool, AllChangesReported: e[10].Bool, Status: e[11].Bool, EventCodeRequested: int(ec)}
	if n[1] != 0 {
		ts.StartTime = time.Unix(n[1], 0).UTC()
	}
	return ts, nil
}

// Features is the Supported_Features bit string for conformance blocks.
func Features(blocks ...int) mms.BitString {
	b := mms.NewBitString(12)
	for _, n := range blocks {
		b.Set(n-1, true)
	}
	return b
}

// Blocks lists the conformance blocks set in Supported_Features.
func Blocks(b mms.BitString) []int {
	var out []int
	for i := 0; i < b.NBits; i++ {
		if b.Get(i) {
			out = append(out, i+1)
		}
	}
	return out
}

// ---- indication point configuration (IEC 60870-6-802 6.2.1, 7.1.1) --------

// PointConfig is an IndicationPointConfig value.
type PointConfig struct {
	PointType      int // 0 state, 1 discrete, 2 real, 3 state supplemental
	QualityClass   int // 0 no quality, 1 quality
	NormalSource   int // coded like Flags.Source
	TimeStampClass int // 0 none, 1 time stamp, 2 extended time stamp
	COVClass       int // 0 no counter, 1 counter
}

// Data encodes the IndicationPointConfig structure.
func (c PointConfig) Data() mms.Data {
	return mms.Structure(mms.Integer(int64(c.PointType)), mms.Integer(int64(c.QualityClass)),
		mms.Integer(int64(c.NormalSource)), mms.Integer(int64(c.TimeStampClass)), mms.Integer(int64(c.COVClass)))
}

func ints(d mms.Data, n int, what string) ([]int64, error) {
	if d.Kind != mms.KStructure || len(d.Elems) != n {
		return nil, fmt.Errorf("%s is a structure of %d integers, got %s", what, n, shape(d))
	}
	out := make([]int64, n)
	for i, e := range d.Elems {
		switch e.Kind {
		case mms.KInt:
			out[i] = e.Int
		case mms.KUint:
			out[i] = int64(e.Uint)
		default:
			return nil, fmt.Errorf("%s component %d is %s, not an integer", what, i+1, e.Kind)
		}
	}
	return out, nil
}

// PointConfigFrom reads an IndicationPointConfig.
func PointConfigFrom(d mms.Data) (PointConfig, error) {
	v, err := ints(d, 5, "an IndicationPointConfig")
	if err != nil {
		return PointConfig{}, err
	}
	c := PointConfig{int(v[0]), int(v[1]), int(v[2]), int(v[3]), int(v[4])}
	// The declared ranges are narrower than the codes 7.1.1 assigns
	// (point type 3, time stamp class 2); the codes win (findings F-502).
	if c.PointType < 0 || c.PointType > 3 || c.QualityClass < 0 || c.QualityClass > 1 || c.NormalSource < 0 ||
		c.NormalSource > 3 || c.TimeStampClass < 0 || c.TimeStampClass > 2 || c.COVClass < 0 || c.COVClass > 1 {
		return PointConfig{}, fmt.Errorf("IndicationPointConfig %v is out of range", v)
	}
	return c, nil
}

// Type selects the point type for the configuration, following the
// selection table of 7.1.1: with a change-of-value counter the Extended
// type; otherwise by quality and time stamp class. A time stamp without
// quality has no type.
func (c PointConfig) Type() (Type, error) {
	base := [...]string{"state", "discrete", "real", "stateSupplemental"}[c.PointType]
	if c.COVClass == 1 {
		return Type(base + "Extended"), nil
	}
	switch {
	case c.QualityClass == 0 && c.TimeStampClass == 0:
		return Type(base), nil
	case c.QualityClass == 1 && c.TimeStampClass == 0:
		return Type(base + "Q"), nil
	case c.QualityClass == 1 && c.TimeStampClass == 1:
		return Type(base + "QTimeTag"), nil
	case c.QualityClass == 1 && c.TimeStampClass == 2:
		return Type(base + "QTimeTagExtended"), nil
	}
	return "", fmt.Errorf("no point type has a time stamp without quality (%+v)", c)
}

// ---- control points (IEC 60870-6-802 5.2.3, 6.2.2, 7.1.2, 8.3) -------------

// Command values of Control_Command (8.3): 0 trip, open, off or lower; 1
// close, on or raise.
const (
	CommandOff = 0
	CommandOn  = 1
)

// Tag codes of TagFlags and Data_StateSupplemental.
const (
	TagNone             = 0
	TagOpenCloseInhibit = 1
	TagCloseInhibit     = 2
)

// TagName names a tag code.
func TagName(t int) string {
	switch t {
	case TagNone:
		return "none"
	case TagOpenCloseInhibit:
		return "open-and-close-inhibit"
	case TagCloseInhibit:
		return "close-only-inhibit"
	}
	return "invalid"
}

// TagValue is a Tag_Value: the tag, its state (armed) and the reason.
type TagValue struct {
	Tag    int
	Armed  bool
	Reason string
}

// Data encodes the Tag_Value structure.
func (t TagValue) Data() mms.Data {
	b := mms.NewBitString(3)
	setTwo(b, 0, t.Tag)
	b.Set(2, t.Armed)
	return mms.Structure(mms.Bits(b), mms.Visible(t.Reason))
}

// TagValueFrom reads a Tag_Value.
func TagValueFrom(d mms.Data) (TagValue, error) {
	if d.Kind != mms.KStructure || len(d.Elems) != 2 || d.Elems[0].Kind != mms.KBitString {
		return TagValue{}, fmt.Errorf("a Tag_Value is {flags, reason}, got %s", shape(d))
	}
	r := d.Elems[1]
	if r.Kind != mms.KVisible && r.Kind != mms.KMMSString {
		return TagValue{}, fmt.Errorf("a tag reason is a string, got %s", r.Kind)
	}
	b := d.Elems[0].Bits
	return TagValue{Tag: two(b, 0), Armed: b.Get(2), Reason: r.Str}, nil
}

// Inhibits reports whether the tag forbids operating a device with the
// value: an open-and-close tag forbids every operation, a close-only tag
// a command to close (CommandOn). Code 3 is undefined and is treated as
// inhibiting everything (findings F-504).
func (t TagValue) Inhibits(command bool, value int64) bool {
	switch t.Tag {
	case TagNone:
		return false
	case TagCloseInhibit:
		return command && value == CommandOn
	}
	return true
}

// SBOState is the SBO structure: the time until which a selection holds
// and whether the device is selected.
type SBOState struct {
	TimeOut  time.Time
	Selected bool
}

// Data encodes the SBO structure.
func (s SBOState) Data() mms.Data {
	return mms.Structure(mms.Integer(gmtSeconds(s.TimeOut)), mms.Boolean(s.Selected))
}

// SBOStateFrom reads the SBO structure.
func SBOStateFrom(d mms.Data) (SBOState, error) {
	if d.Kind != mms.KStructure || len(d.Elems) != 2 || d.Elems[1].Kind != mms.KBool {
		return SBOState{}, fmt.Errorf("an SBO value is {timeout, selected}, got %s", shape(d))
	}
	t, err := timeOf(d.Elems[0])
	if err != nil {
		return SBOState{}, err
	}
	return SBOState{TimeOut: t, Selected: d.Elems[1].Bool}, nil
}

// CheckBackFrom reads an SBO_CheckBackName (a 16-bit integer).
func CheckBackFrom(d mms.Data) (int64, error) {
	v := d.Int
	switch d.Kind {
	case mms.KInt:
	case mms.KUint:
		v = int64(d.Uint)
	default:
		return 0, fmt.Errorf("a check-back name is an integer, got %s", d.Kind)
	}
	if v < -32768 || v > 65535 {
		return 0, fmt.Errorf("check-back name %d does not fit 16 bits", v)
	}
	return v, nil
}

// ControlConfig is a ControlConfig value.
type ControlConfig struct {
	ControlPointType int // 0 command, 1 setpoint
	SetPointType     int // 1 discrete, 2 real (0 for commands)
	DeviceClass      int // 0 direct, 1 select-before-operate
	TagClass         int // 0 not taggable, 1 taggable
}

// Data encodes the ControlConfig structure.
func (c ControlConfig) Data() mms.Data {
	return mms.Structure(mms.Integer(int64(c.ControlPointType)), mms.Integer(int64(c.SetPointType)),
		mms.Integer(int64(c.DeviceClass)), mms.Integer(int64(c.TagClass)))
}

// ControlConfigFrom reads a ControlConfig.
func ControlConfigFrom(d mms.Data) (ControlConfig, error) {
	v, err := ints(d, 4, "a ControlConfig")
	if err != nil {
		return ControlConfig{}, err
	}
	return ControlConfig{int(v[0]), int(v[1]), int(v[2]), int(v[3])}, nil
}

// Kind is the device kind of the configuration: command, real or
// discrete; other combinations are invalid (7.1.2).
func (c ControlConfig) Kind() (string, error) {
	switch {
	case c.ControlPointType == 0:
		return "command", nil
	case c.ControlPointType == 1 && c.SetPointType == 2:
		return "real", nil
	case c.ControlPointType == 1 && c.SetPointType == 1:
		return "discrete", nil
	}
	return "", fmt.Errorf("ControlConfig %+v is not a command or a real or discrete setpoint", c)
}

// ---- information buffer (IEC 60870-6-802 5.4, 6.4, 7.3) --------------------

// InfoMessage is an InformationBuffer object: the InfoMessHeader and the
// valid part of the InfoBufXX octets.
type InfoMessage struct {
	InfoReference  int64
	LocalReference int64
	MessageID      int64
	Data           []byte
}

// InfoBufName is the type name of an information buffer of n octets
// (InfoBuf64, InfoBuf256 …; no leading zeros).
func InfoBufName(n int) string { return fmt.Sprintf("InfoBuf%d", n) }

// HeaderData encodes the InfoMessHeader of the message.
func (m InfoMessage) HeaderData() mms.Data {
	return mms.Structure(mms.Integer(m.InfoReference), mms.Integer(m.LocalReference), mms.Integer(m.MessageID),
		mms.Integer(int64(len(m.Data))))
}

// BufferData encodes the InfoBufXX value, padded to size octets when size
// is larger than the message.
func (m InfoMessage) BufferData(size int) mms.Data {
	b := make([]byte, max(size, len(m.Data)))
	copy(b, m.Data)
	return mms.Octets(b)
}

// InfoMessageFrom reads an InfoMessHeader and its InfoBufXX value; only
// the first Size octets are the message.
func InfoMessageFrom(header, buf mms.Data) (InfoMessage, error) {
	v, err := ints(header, 4, "an InfoMessHeader")
	if err != nil {
		return InfoMessage{}, err
	}
	if buf.Kind != mms.KOctets {
		return InfoMessage{}, fmt.Errorf("an information buffer is an octet string, got %s", buf.Kind)
	}
	if v[3] < 0 || v[3] > int64(len(buf.Bytes)) {
		return InfoMessage{}, fmt.Errorf("the message size %d exceeds its %d-octet buffer", v[3], len(buf.Bytes))
	}
	return InfoMessage{InfoReference: v[0], LocalReference: v[1], MessageID: v[2], Data: buf.Bytes[:v[3]]}, nil
}

// IsInfoHeader reports whether d has the shape of an InfoMessHeader.
func IsInfoHeader(d mms.Data) bool {
	_, err := ints(d, 4, "")
	return err == nil
}
