package tase2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

// ---- time types (IEC 60870-6-503 8.2.4 to 8.2.6) ---------------------------

// Time units of the GMTBased and TimeInterval types.
const (
	UnitMillisecond = time.Millisecond // TimeIntervalL16, TimeIntervalL32
	UnitSecond      = time.Second      // GMTBasedS, TimeIntervalS
	UnitMinute      = time.Minute      // GMTBasedM, TimeIntervalM
	UnitHour        = time.Hour        // GMTBasedH, TimeIntervalH
	UnitDay         = 24 * time.Hour   // GMTBasedD, TimeIntervalD
)

// GMTBasedS is the Integer32 count of whole seconds since 1970-01-01
// 00:00:00 GMT; a zero time is 0.
func GMTBasedS(t time.Time) int64 { return GMTBased(t, UnitSecond) }

// GMTBased is the Integer32 count of whole units since 1970-01-01 GMT
// (GMTBasedS, M, H, D). The clauses call the first unit "number one" but
// count from zero like the Unix time (findings F-514).
func GMTBased(t time.Time, unit time.Duration) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix() / int64(unit/time.Second)
}

// FromGMTBased is the start of a GMTBased count.
func FromGMTBased(v int64, unit time.Duration) time.Time {
	return time.Unix(v*int64(unit/time.Second), 0).UTC()
}

// Interval encodes a length of time as a TimeInterval type: unit
// UnitMillisecond with 16 bits is TimeIntervalL16, and so on. Values
// that do not fit the width are refused.
func Interval(d time.Duration, unit time.Duration, bits int) (mms.Data, error) {
	v := int64(d / unit)
	if v < -(1<<(bits-1)) || v > 1<<(bits-1)-1 {
		return mms.Data{}, fmt.Errorf("%v does not fit a %d-bit interval of %v", d, bits, unit)
	}
	return mms.Integer(v), nil
}

// IntervalFrom reads a TimeInterval integer of the given unit.
func IntervalFrom(d mms.Data, unit time.Duration) (time.Duration, error) {
	v, ok := intOf(d)
	if !ok {
		return 0, fmt.Errorf("a time interval is an integer, got %s", d.Kind)
	}
	return time.Duration(v) * unit, nil
}

// TimeStampExtended encodes {GMTBasedS, Milliseconds TimeIntervalL16}.
func TimeStampExtended(t time.Time) mms.Data {
	ms := int64(0)
	if !t.IsZero() {
		ms = int64(t.Nanosecond() / 1e6)
	}
	return mms.Structure(mms.Integer(GMTBasedS(t)), mms.Integer(ms))
}

// ---- Supported_Features and TASE.2_Version (8.2.9, 8.2.10) ----------------

// Conformance blocks of IEC 60870-6-702:2014 Table A.2; SupportedFeatures
// bit n-1 is block n (IEC 60870-6-503:2014 8.2.9, which reserves the bits
// of blocks 3 and 6 to 10; findings F-870).
const (
	BlockBasic              = 1 // basic services (mandatory)
	BlockExtendedConditions = 2 // object change, integrity, RBE, critical, TLE, buffer time
	BlockBlockedTransfers   = 3 // Block Data
	BlockInformationMessage = 4 // information message transfer set and buffers
	BlockDeviceControl      = 5 // SBO device control
	BlockPrograms           = 6 // outside the scope of 6-702 (i)
	BlockEvents             = 7 // outside the scope of 6-702 (i); event management (A.26 c3)
	BlockAccounts           = 8 // outside the scope of 6-702 (i)
	BlockTimeSeries         = 9 // outside the scope of 6-702 (i)
)

var blockNames = map[int]string{BlockBasic: "basic services", BlockExtendedConditions: "extended conditions",
	BlockBlockedTransfers: "blocked transfers", BlockInformationMessage: "information message",
	BlockDeviceControl: "SBO device control", BlockPrograms: "programs", BlockEvents: "events",
	BlockAccounts: "accounts", BlockTimeSeries: "time series"}

// ClientBlocks are the conformance blocks the client implements (the
// client side of pics.yaml Table A.2); it uses each only when the peer
// lists it.
var ClientBlocks = []int{BlockBasic, BlockExtendedConditions, BlockBlockedTransfers, BlockInformationMessage,
	BlockDeviceControl, BlockEvents}

// BlockName names a conformance block as IEC 60870-6-702:2014 Table A.2
// does.
func BlockName(n int) string {
	if s, ok := blockNames[n]; ok {
		return s
	}
	return fmt.Sprintf("block %d (not defined by IEC 60870-6-702:2014)", n)
}

// Supports reports whether a Supported_Features value sets block n.
func Supports(b mms.BitString, n int) bool { return n >= 1 && n <= b.NBits && b.Get(n-1) }

// Version is TASE.2_Version, {MajorVersionNumber, MinorVersionNumber}
// (both Integer16). This edition is 2000.08.
type Version struct{ Major, Minor int }

// Edition2014 is the version of IEC 60870-6-503:2014 (8.3.4).
var Edition2014 = Version{2000, 8}

// String writes the version as the standard does, "2000.08".
func (v Version) String() string { return fmt.Sprintf("%d.%02d", v.Major, v.Minor) }

// Data encodes the TASE.2Version structure.
func (v Version) Data() mms.Data {
	return mms.Structure(mms.Integer(int64(v.Major)), mms.Integer(int64(v.Minor)))
}

// VersionFrom reads a TASE.2Version.
func VersionFrom(d mms.Data) (Version, error) {
	v, err := ints(d, 2, "a TASE.2Version")
	if err != nil {
		return Version{}, err
	}
	for _, x := range v {
		if x < -32768 || x > 32767 {
			return Version{}, fmt.Errorf("TASE.2 version component %d is not an Integer16", x)
		}
	}
	return Version{int(v[0]), int(v[1])}, nil
}

// ParseVersion reads "2000.08" or "2000.8".
func ParseVersion(s string) (Version, error) {
	a, b, ok := strings.Cut(s, ".")
	ma, err1 := strconv.Atoi(a)
	mi, err2 := strconv.Atoi(b)
	if !ok || err1 != nil || err2 != nil || ma < 0 || mi < 0 || ma > 32767 || mi > 32767 {
		return Version{}, fmt.Errorf("TASE.2 version %q is not major.minor, such as 2000.08", s)
	}
	return Version{ma, mi}, nil
}

// ---- critical transfer report acknowledgement (7.2.5.5.2) ------------------

// AckReport builds the InformationReport a client sends to acknowledge a
// critical transfer report: Transfer_Report_ACK carrying the transfer set
// name, and Transfer_Set_Time_Stamp carrying the time stamp the report
// had, both in the transfer set's domain.
func AckReport(ts mms.ObjectName, stamp mms.Data) (mms.VariableSpec, []mms.AccessResult) {
	return mms.VariableSpec{Vars: []mms.ObjectName{mms.DomainName(ts.Domain, VarReportACK), mms.DomainName(ts.Domain, VarTSTimeStamp)}},
		[]mms.AccessResult{{Data: ObjectNameData(ts)}, {Data: stamp}}
}

// NackReport builds the negative acknowledgement of a transfer report
// whose data set is not the transfer set's: Transfer_Report_NACK carrying
// the transfer set name, in its domain.
func NackReport(ts mms.ObjectName) (mms.VariableSpec, []mms.AccessResult) {
	return mms.VariableSpec{Vars: []mms.ObjectName{mms.DomainName(ts.Domain, VarReportNACK)}},
		[]mms.AccessResult{{Data: ObjectNameData(ts)}}
}

// Ack is a decoded Transfer_Report_ACK or NACK report (server side).
type Ack struct {
	TransferSet mms.ObjectName
	Stamp       int64 // 0 for a NACK
	Negative    bool
}

// AckFrom recognises an acknowledgement report; ok is false for other
// reports.
func AckFrom(r mms.InformationReport) (a Ack, ok bool, err error) {
	if len(r.Spec.Vars) == 0 || len(r.Spec.Vars) != len(r.Results) {
		return Ack{}, false, nil
	}
	switch r.Spec.Vars[0].Item {
	case VarReportACK:
	case VarReportNACK:
		a.Negative = true
	default:
		return Ack{}, false, nil
	}
	if a.TransferSet, err = ObjectNameFrom(r.Results[0].Data); err != nil {
		return Ack{}, true, err
	}
	if !a.Negative {
		if len(r.Results) < 2 || r.Spec.Vars[1].Item != VarTSTimeStamp {
			return Ack{}, true, errors.New("an acknowledgement carries Transfer_Set_Time_Stamp")
		}
		v, ok := intOf(r.Results[1].Data)
		if !ok {
			return Ack{}, true, errors.New("Transfer_Set_Time_Stamp is GMTBasedS")
		}
		a.Stamp = v
	}
	return a, true, nil
}

// ---- blocked transfer reports (7.2.5.5.3, Block Data) ----------------------

// Blocking rules of a blocked transfer report's first octet.
const (
	RuleAll     = 0 // no RBE: every member's value in order
	RuleOffset1 = 1 // RBE: 1-octet position, then the value
	RuleOffset2 = 2 // RBE: 2-octet position, then the value
)

// storage writes a value in its octet-aligned storage form: IEC
// 60870-6-802 foundation types in component order, integers and floats
// big-endian (findings F-516).
func storage(t Type, d mms.Data) ([]byte, error) {
	l, ok := types[t]
	if !ok {
		return nil, fmt.Errorf("unknown point type %q", t)
	}
	parts := []mms.Data{d}
	if len(l.fields) > 1 {
		if d.Kind != mms.KStructure || len(d.Elems) != len(l.fields) {
			return nil, fmt.Errorf("a %s is a structure of %d components", t, len(l.fields))
		}
		parts = d.Elems
	}
	var b []byte
	for i, f := range l.fields {
		p := parts[i]
		switch f {
		case fValue:
			if l.base == "real" {
				b = binary.BigEndian.AppendUint32(b, math.Float32bits(float32(p.Float)))
			} else {
				v, _ := intOf(p)
				b = binary.BigEndian.AppendUint32(b, uint32(int32(v)))
			}
		case fState, fFlags, fSupp, fSingleFlags, fEventFlags, fPackedFlags:
			var o byte
			if len(p.Bits.Bits) > 0 {
				o = p.Bits.Bits[0]
			}
			b = append(b, o)
		case fTime:
			v, _ := intOf(p)
			b = binary.BigEndian.AppendUint32(b, uint32(int32(v)))
		case fTimeExt:
			if len(p.Elems) != 2 {
				return nil, errors.New("an extended time stamp is {seconds, milliseconds}")
			}
			s, _ := intOf(p.Elems[0])
			ms, _ := intOf(p.Elems[1])
			b = binary.BigEndian.AppendUint32(b, uint32(int32(s)))
			b = binary.BigEndian.AppendUint16(b, uint16(int16(ms)))
		case fCOV:
			v, _ := intOf(p)
			b = binary.BigEndian.AppendUint16(b, uint16(v))
		case fOpTime:
			v, _ := intOf(p)
			b = binary.BigEndian.AppendUint16(b, uint16(int16(v)))
		}
	}
	return b, nil
}

// storageSize is the octet length of a type's storage form.
func storageSize(t Type) int {
	n := 0
	l := types[t]
	for _, f := range l.fields {
		switch f {
		case fValue, fTime:
			n += 4
		case fTimeExt:
			n += 6
		case fCOV, fOpTime:
			n += 2
		default:
			n++
		}
	}
	return n
}

// fromStorage reads a value from its storage form.
func fromStorage(t Type, b []byte) (mms.Data, error) {
	l, ok := types[t]
	if !ok {
		return mms.Data{}, fmt.Errorf("unknown point type %q", t)
	}
	if len(b) < storageSize(t) {
		return mms.Data{}, fmt.Errorf("blocked data ends inside a %s", t)
	}
	var out []mms.Data
	bits := func(n int) mms.Data {
		v := mms.BitString{Bits: []byte{b[0]}, NBits: n}
		b = b[1:]
		return mms.Bits(v)
	}
	for _, f := range l.fields {
		switch f {
		case fValue:
			u := binary.BigEndian.Uint32(b)
			if l.base == "real" {
				out = append(out, mms.Float32(float64(math.Float32frombits(u))))
			} else {
				out = append(out, mms.Integer(int64(int32(u))))
			}
			b = b[4:]
		case fState, fFlags, fSupp, fSingleFlags, fEventFlags, fPackedFlags:
			out = append(out, bits(8))
		case fTime:
			out = append(out, mms.Integer(int64(int32(binary.BigEndian.Uint32(b)))))
			b = b[4:]
		case fTimeExt:
			out = append(out, mms.Structure(mms.Integer(int64(int32(binary.BigEndian.Uint32(b)))),
				mms.Integer(int64(int16(binary.BigEndian.Uint16(b[4:]))))))
			b = b[6:]
		case fCOV:
			out = append(out, mms.Unsigned(uint64(binary.BigEndian.Uint16(b))))
			b = b[2:]
		case fOpTime:
			out = append(out, mms.Integer(int64(int16(binary.BigEndian.Uint16(b)))))
			b = b[2:]
		}
	}
	if len(out) == 1 {
		return out[0], nil
	}
	return mms.Structure(out...), nil
}

// BlockMember is one member of a data set in a blocked report: its
// position in the named variable list (special transfer objects count)
// and its point type.
type BlockMember struct {
	Pos  int
	Type Type
}

// EncodeBlock builds the octet string of a blocked transfer report.
// With RuleAll every member is written in order; with the offset rules
// only the members whose value is given (values[i] non-nil).
func EncodeBlock(rule int, members []BlockMember, values []*mms.Data) ([]byte, error) {
	b := []byte{byte(rule)}
	for i, m := range members {
		v := values[i]
		if v == nil {
			if rule == RuleAll {
				return nil, errors.New("a blocked report without RBE carries every member")
			}
			continue
		}
		switch rule {
		case RuleOffset1:
			if m.Pos > 255 {
				return nil, fmt.Errorf("position %d does not fit rule 1", m.Pos)
			}
			b = append(b, byte(m.Pos))
		case RuleOffset2:
			if m.Pos > 65535 {
				return nil, fmt.Errorf("position %d does not fit rule 2", m.Pos)
			}
			b = binary.BigEndian.AppendUint16(b, uint16(m.Pos))
		case RuleAll:
		default:
			return nil, fmt.Errorf("blocking rule %d is not 0, 1 or 2", rule)
		}
		s, err := storage(m.Type, *v)
		if err != nil {
			return nil, err
		}
		b = append(b, s...)
	}
	return b, nil
}

// DecodeBlock reads a blocked transfer report's octet string into the
// values of the members it carries, by position.
func DecodeBlock(b []byte, members []BlockMember) (map[int]mms.Data, error) {
	if len(b) == 0 {
		return nil, errors.New("a blocked report has at least the rule octet")
	}
	rule, b := int(b[0]), b[1:]
	out := map[int]mms.Data{}
	byPos := map[int]Type{}
	for _, m := range members {
		byPos[m.Pos] = m.Type
	}
	switch rule {
	case RuleAll:
		for _, m := range members {
			d, err := fromStorage(m.Type, b)
			if err != nil {
				return nil, err
			}
			out[m.Pos] = d
			b = b[storageSize(m.Type):]
		}
	case RuleOffset1, RuleOffset2:
		for len(b) > 0 {
			var pos int
			if rule == RuleOffset1 {
				pos, b = int(b[0]), b[1:]
			} else {
				if len(b) < 2 {
					return nil, errors.New("blocked data ends inside a position")
				}
				pos, b = int(binary.BigEndian.Uint16(b)), b[2:]
			}
			t, ok := byPos[pos]
			if !ok {
				return nil, fmt.Errorf("blocked data names position %d, which is not a member", pos)
			}
			d, err := fromStorage(t, b)
			if err != nil {
				return nil, err
			}
			out[pos] = d
			b = b[storageSize(t):]
		}
	default:
		return nil, fmt.Errorf("blocking rule %d is not 0, 1 or 2", rule)
	}
	if rule == RuleAll && len(b) != 0 {
		return nil, fmt.Errorf("%d octets follow the last member", len(b))
	}
	return out, nil
}

// ---- information message buffers (503 6.8, 8.5, G.3.7) ----------------------

// InfoBufferSizes are the InfoBuff sizes our server offers; a message
// goes in the smallest that holds it (larger messages in a multiple of
// 1024 octets).
var InfoBufferSizes = []int{64, 256, 1024}

// InfoBufferSize is the smallest buffer size for n octets.
func InfoBufferSize(n int) int {
	for _, s := range InfoBufferSizes {
		if n <= s {
			return s
		}
	}
	return (n + 1023) / 1024 * 1024
}

// IsInfoBuffer reports whether an item names an information buffer
// variable: Info_Buff_<n>, or Info_Buf_<n> as 6.8 spells it (findings
// F-517).
func IsInfoBuffer(item string) bool {
	for _, p := range []string{InfoBufferPrefix, "Info_Buf_"} {
		if rest, ok := strings.CutPrefix(item, p); ok {
			_, err := strconv.Atoi(rest)
			return err == nil
		}
	}
	return false
}

// ---- device outage reports (IEC 60870-6-802 5.3, 6.3, 7.2) ------------------

// Device outage report variables, by activity.
const (
	VarOutageNew    = "DO_New_Sched"
	VarOutageRevise = "DO_Rev_Sched"
	VarOutageCancel = "DO_Cancel"
	VarOutageActual = "DO_Actual"
)

var (
	outageCommon = []string{"outageReferenceId", "owningUtilityId", "timeStamp", "stationName", "deviceName",
		"deviceType", "deviceNumber", "deviceRating", "activityDateAndTime"}
	outageFields = map[string][]string{
		VarOutageNew: append(append([]string(nil), outageCommon...), "planType", "plannedOpenOrOutOfService",
			"plannedCloseOrInService", "outagePeriod", "outageType", "outageAmountType", "amount",
			"upperOperatingLimit", "lowerOperatingLimit", "class", "comments", "outageEffect"),
		VarOutageCancel: append(append([]string(nil), outageCommon...), "comments", "outageEffect"),
		VarOutageActual: append(append([]string(nil), outageCommon...), "action", "affectedAmount", "comments", "outageEffect"),
	}
	outageCodes = map[string][]string{
		"deviceType":       {"other", "generator", "transformer", "capacitor", "transmission-circuit", "breaker-switch", "inductor"},
		"planType":         {"scheduled", "estimated"},
		"outagePeriod":     {"other", "continuous", "daily", "weekdays"},
		"outageType":       {"forced", "maintenance", "partial", "economy", "unplanned", "forced", "other"},
		"outageAmountType": {"partial", "full"},
		"class":            {"out-of-service", "in-service"},
		"action":           {"tripped", "offline", "online", "open", "close"},
	}
	outageTimes = map[string]bool{"timeStamp": true, "activityDateAndTime": true, "plannedOpenOrOutOfService": true,
		"plannedCloseOrInService": true}
)

func init() { outageFields[VarOutageRevise] = outageFields[VarOutageNew] }

// IsOutage reports whether an item names a device outage report variable.
func IsOutage(item string) bool { _, ok := outageFields[item]; return ok }

// OutageFrom decodes a device outage report variable (DONewRevSched,
// DOCancel or DOActual by name) into named fields; codes become their
// names and times RFC 3339 text.
func OutageFrom(item string, d mms.Data) (map[string]any, error) {
	names, ok := outageFields[item]
	if !ok {
		return nil, fmt.Errorf("%s is not a device outage variable", item)
	}
	if d.Kind != mms.KStructure || len(d.Elems) != len(names) {
		return nil, fmt.Errorf("%s is a structure of %d components, got %s", item, len(names), shape(d))
	}
	activity := map[string]string{VarOutageNew: "new-plan", VarOutageRevise: "revise", VarOutageCancel: "cancel", VarOutageActual: "actual"}
	out := map[string]any{"activity": activity[item]}
	for i, n := range names {
		e := d.Elems[i]
		switch {
		case outageTimes[n]:
			v, ok := intOf(e)
			if !ok {
				return nil, fmt.Errorf("%s %s is GMTBasedS", item, n)
			}
			if v != 0 {
				out[n] = time.Unix(v, 0).UTC().Format(time.RFC3339)
			}
		case outageCodes[n] != nil:
			v, ok := intOf(e)
			if !ok {
				return nil, fmt.Errorf("%s %s is an integer code", item, n)
			}
			if v >= 0 && int(v) < len(outageCodes[n]) {
				out[n] = outageCodes[n][v]
			} else {
				out[n] = v
			}
		case e.Kind == mms.KFloat:
			out[n] = e.Float
		case e.Kind == mms.KVisible || e.Kind == mms.KMMSString:
			out[n] = e.Str
		default:
			v, ok := intOf(e)
			if !ok {
				return nil, fmt.Errorf("%s %s has type %s", item, n, e.Kind)
			}
			out[n] = v
		}
	}
	return out, nil
}

// Outage report fields that are Data_Real or text (IEC 60870-6-802 6.3).
var (
	outageReals = map[string]bool{"deviceRating": true, "amount": true, "upperOperatingLimit": true,
		"lowerOperatingLimit": true, "affectedAmount": true}
	outageText = map[string]int{"stationName": 32, "deviceName": 32, "comments": 128, "outageEffect": 128}
)

// OutageItem is the report variable of an outage activity: new-plan,
// revise, cancel or actual (IEC 60870-6-802 7.2).
func OutageItem(activity string) (string, error) {
	switch activity {
	case "new-plan":
		return VarOutageNew, nil
	case "revise":
		return VarOutageRevise, nil
	case "cancel":
		return VarOutageCancel, nil
	case "actual":
		return VarOutageActual, nil
	}
	return "", fmt.Errorf("outage activity %q is not new-plan, revise, cancel or actual", activity)
}

// OutageData encodes a device outage report from named fields (the form
// OutageFrom returns): codes by name or number, times as RFC 3339 text or
// GMTBasedS seconds, missing fields as zero or empty.
func OutageData(item string, f map[string]any) (mms.Data, error) {
	names, ok := outageFields[item]
	if !ok {
		return mms.Data{}, fmt.Errorf("%s is not a device outage variable", item)
	}
	out := make([]mms.Data, len(names))
	for i, n := range names {
		v, has := f[n]
		switch {
		case outageTimes[n]:
			var secs int64
			switch x := v.(type) {
			case string:
				t, err := time.Parse(time.RFC3339, x)
				if err != nil {
					return mms.Data{}, fmt.Errorf("%s %s: %w", item, n, err)
				}
				secs = t.Unix()
			case float64:
				secs = int64(x)
			case int64:
				secs = x
			case nil:
			default:
				return mms.Data{}, fmt.Errorf("%s %s is a time", item, n)
			}
			out[i] = mms.Integer(secs)
		case outageCodes[n] != nil:
			code := int64(-1)
			switch x := v.(type) {
			case string:
				for j, name := range outageCodes[n] {
					if name == x {
						code = int64(j)
						break
					}
				}
			case float64:
				code = int64(x)
			case int64:
				code = x
			case nil:
				code = 0
			}
			if code < 0 || code > 32767 {
				return mms.Data{}, fmt.Errorf("%s %s %v is not one of %v", item, n, v, outageCodes[n])
			}
			out[i] = mms.Integer(code)
		case outageReals[n]:
			x, _ := v.(float64)
			if has && v != nil {
				if _, ok := v.(float64); !ok {
					return mms.Data{}, fmt.Errorf("%s %s is a number", item, n)
				}
			}
			out[i] = mms.Float32(x)
		case outageText[n] > 0:
			s, _ := v.(string)
			if len(s) > outageText[n] {
				return mms.Data{}, fmt.Errorf("%s %s is at most %d characters", item, n, outageText[n])
			}
			out[i] = mms.Visible(s)
		default:
			var x int64
			switch y := v.(type) {
			case float64:
				x = int64(y)
			case int64:
				x = y
			case nil:
			default:
				return mms.Data{}, fmt.Errorf("%s %s is an integer", item, n)
			}
			if x < math.MinInt32 || x > math.MaxInt32 {
				return mms.Data{}, fmt.Errorf("%s %s does not fit 32 bits", item, n)
			}
			out[i] = mms.Integer(x)
		}
	}
	return mms.Structure(out...), nil
}

// ClientCapabilities are the services and parameter CBBs our TASE.2
// client proposes in its initiate request: those IEC 60870-6-702:2014
// Tables A.17 to A.23 require of a client (GetNameList, Identify, Read,
// Write, GetVariableAccessAttributes, the named variable list services,
// InformationReport, Conclude) and, with event enrollments configured,
// the event management services of block 7 (Table A.26); no service the
// profile excludes (Status, journals, files; F-879). Parameter CBBs:
// str1, str2, vnam, valt (alternate access in variable list attributes,
// A.41), vlis and cei.
func ClientCapabilities(events bool) mms.Capabilities {
	c := mms.Capabilities{MaxPDU: 65000, MaxOutstanding: 5, Nesting: 10,
		Parameters: []int{mms.CBBStr1, mms.CBBStr2, mms.CBBVnam, mms.CBBValt, mms.CBBVlis, mms.CBBCei},
		Services: []int{mms.SvcGetNameList, mms.SvcIdentify, mms.SvcRead, mms.SvcWrite, mms.SvcGetVariableAccessAttributes,
			mms.SvcDefineNamedVariableList, mms.SvcGetNamedVariableListAttributes, mms.SvcDeleteNamedVariableList,
			mms.BitInformationReport, mms.BitConclude}}
	if events {
		c.Services = append(c.Services, mms.EventServices...)
	}
	return c
}

// NeedsAck reports whether a notification needs acknowledging under the
// rule it carries (ISO 9506-1:2003 21.1.2): a transition to active under
// simple, ack-active or ack-all, to idle under ack-all.
func NeedsAck(n mms.EventNotification) bool {
	if !n.HasAckRule || n.NoState {
		return false
	}
	switch n.State {
	case mms.ECStateActive:
		return n.AckRule != mms.AckNone
	case mms.ECStateIdle:
		return n.AckRule == mms.AckAll
	}
	return false
}
