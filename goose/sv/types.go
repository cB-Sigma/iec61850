package sv

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

// Type is a basic data type of a sampled values data set member (8.6,
// Table 15). Only FCDA of basic types are members (5.4).
type Type int

// Types of Table 15, and Quality with the mapping of Table 21.
const (
	Boolean Type = iota + 1
	Int8
	Int16
	Int32
	Int64
	Int8U
	Int16U
	Int32U
	Float32
	Enumerated
	CodedEnum
	OctetString
	VisibleString
	UnicodeString
	ObjectName
	ObjectReference
	TimestampType
	EntryTime
	EntryID
	Currency
	BitString
	QualityType
)

var typeInfo = map[Type]struct {
	name string
	size int
}{
	Boolean: {"BOOLEAN", 1}, Int8: {"INT8", 1}, Int16: {"INT16", 2}, Int32: {"INT32", 4}, Int64: {"INT64", 8},
	Int8U: {"INT8U", 1}, Int16U: {"INT16U", 2}, Int32U: {"INT32U", 4}, Float32: {"FLOAT32", 4},
	Enumerated: {"ENUMERATED", 4}, CodedEnum: {"CODED ENUM", 4}, OctetString: {"OCTET STRING", 20},
	VisibleString: {"VISIBLE STRING", 35}, UnicodeString: {"UNICODE STRING", 20}, ObjectName: {"ObjectName", 20},
	ObjectReference: {"ObjectReference", 20}, TimestampType: {"Timestamp", 8}, EntryTime: {"EntryTime", 6},
	EntryID: {"EntryID", 8}, Currency: {"Currency", 4}, BitString: {"BITSTRING", 4}, QualityType: {"Quality", 4},
}

// String names the value.
func (t Type) String() string {
	if i, ok := typeInfo[t]; ok {
		return i.name
	}
	return fmt.Sprintf("Type(%d)", int(t))
}

// Size is the number of octets the type takes in the sample (Table 15).
func (t Type) Size() int { return typeInfo[t].size }

// LE is the data set of the IEC 61850-9-2 LE profile (four currents and
// four voltages, each an INT32 value and its quality); 9-2 itself leaves
// the data set to the configuration.
var LE = []Type{Int32, QualityType, Int32, QualityType, Int32, QualityType, Int32, QualityType,
	Int32, QualityType, Int32, QualityType, Int32, QualityType, Int32, QualityType}

// SampleSize is the cumulated size of the data set (SIZE(n) of the
// sample component, Table 14).
func SampleSize(types []Type) (int, error) {
	n := 0
	for _, t := range types {
		s := t.Size()
		if s == 0 {
			return 0, fmt.Errorf("sv: %v is not a basic type of Table 15", t)
		}
		n += s
	}
	return n, nil
}

// BitStringBit is the mask of bit n of a 32-bit BITSTRING read as a
// big-endian word: bit 0 is the most significant bit of the first octet
// (Table 15).
func BitStringBit(n int) uint32 { return 1 << (31 - n) }

// DecodeSample splits a sample into member values by the data set's
// types: bool, int64 (signed integers and ENUMERATED), uint64 (unsigned
// integers and CODED ENUM), float32, string (text types), []byte
// (EntryTime, EntryID), Timestamp, uint32 (BITSTRING) and Quality.
func DecodeSample(types []Type, b []byte) ([]any, error) {
	n, err := SampleSize(types)
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, fmt.Errorf("sv: a sample of %d octets for a data set of %d", len(b), n)
	}
	out := make([]any, len(types))
	for i, t := range types {
		v := b[:t.Size()]
		b = b[t.Size():]
		switch t {
		case Boolean:
			out[i] = v[0] != 0 // 0 FALSE, anything else TRUE
		case Int8:
			out[i] = int64(int8(v[0]))
		case Int16:
			out[i] = int64(int16(binary.BigEndian.Uint16(v)))
		case Int32, Enumerated:
			out[i] = int64(int32(binary.BigEndian.Uint32(v)))
		case Int64:
			out[i] = int64(binary.BigEndian.Uint64(v))
		case Int8U:
			out[i] = uint64(v[0])
		case Int16U:
			out[i] = uint64(binary.BigEndian.Uint16(v))
		case Int32U, CodedEnum:
			out[i] = uint64(binary.BigEndian.Uint32(v))
		case Float32:
			out[i] = math.Float32frombits(binary.BigEndian.Uint32(v))
		case OctetString, VisibleString, UnicodeString, ObjectName, ObjectReference, Currency:
			// Null terminated text; a field full to its size without a
			// NUL is taken whole (F-1083).
			if j := bytes.IndexByte(v, 0); j >= 0 {
				v = v[:j]
			}
			out[i] = string(v)
		case TimestampType:
			out[i] = parseTimestamp(v)
		case EntryTime, EntryID:
			out[i] = append([]byte(nil), v...)
		case BitString:
			out[i] = binary.BigEndian.Uint32(v)
		case QualityType:
			out[i] = Quality(binary.BigEndian.Uint32(v))
		}
	}
	return out, nil
}

func asInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int8:
		return int64(x), true
	case int16:
		return int64(x), true
	case int32:
		return int64(x), true
	case int64:
		return x, true
	case uint8:
		return int64(x), true
	case uint16:
		return int64(x), true
	case uint32:
		return int64(x), true
	case uint64:
		if x <= math.MaxInt64 {
			return int64(x), true
		}
	}
	return 0, false
}

// EncodeSample packs member values (the Go types DecodeSample gives, or
// any integer type for integers) into a sample, refusing values outside
// their type and the formerly reserved validity (C.3.5).
func EncodeSample(types []Type, values []any) ([]byte, error) {
	if len(types) != len(values) {
		return nil, fmt.Errorf("sv: %d values for %d members", len(values), len(types))
	}
	n, err := SampleSize(types)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, n)
	for i, t := range types {
		v := values[i]
		bad := fmt.Errorf("sv: member %d (%v) cannot take %v (%T)", i+1, t, v, v)
		switch t {
		case Boolean:
			x, ok := v.(bool)
			if !ok {
				return nil, bad
			}
			if x {
				b = append(b, 1)
			} else {
				b = append(b, 0)
			}
		case Int8, Int16, Int32, Int64, Enumerated, Int8U, Int16U, Int32U, CodedEnum:
			var lo, hi int64
			switch t {
			case Int8:
				lo, hi = math.MinInt8, math.MaxInt8
			case Int16:
				lo, hi = math.MinInt16, math.MaxInt16
			case Int32, Enumerated:
				lo, hi = math.MinInt32, math.MaxInt32
			case Int64:
				lo, hi = math.MinInt64, math.MaxInt64
			case Int8U:
				hi = math.MaxUint8
			case Int16U:
				hi = math.MaxUint16
			default:
				hi = math.MaxUint32
			}
			x, ok := asInt(v)
			if !ok || x < lo || x > hi {
				return nil, bad
			}
			switch t.Size() {
			case 1:
				b = append(b, byte(x))
			case 2:
				b = binary.BigEndian.AppendUint16(b, uint16(x))
			case 4:
				b = binary.BigEndian.AppendUint32(b, uint32(x))
			default:
				b = binary.BigEndian.AppendUint64(b, uint64(x))
			}
		case Float32:
			var f float32
			switch x := v.(type) {
			case float32:
				f = x
			case float64:
				f = float32(x)
			default:
				return nil, bad
			}
			b = binary.BigEndian.AppendUint32(b, math.Float32bits(f))
		case OctetString, VisibleString, UnicodeString, ObjectName, ObjectReference, Currency:
			s, ok := v.(string)
			// Room for the terminating NUL; text types other than the
			// Unicode one are ASCII (Table 15).
			if !ok || len(s) >= t.Size() || strings.IndexByte(s, 0) >= 0 || (t != UnicodeString && !ascii(s)) || (t == UnicodeString && !utf8.ValidString(s)) {
				return nil, bad
			}
			f := make([]byte, t.Size())
			copy(f, s)
			b = append(b, f...)
		case TimestampType:
			x, ok := v.(Timestamp)
			if !ok || x.Fraction > 0xFFFFFF {
				return nil, bad
			}
			b = append(b, x.Bytes()...)
		case EntryTime, EntryID:
			x, ok := v.([]byte)
			if !ok || len(x) != t.Size() {
				return nil, bad
			}
			b = append(b, x...)
		case BitString:
			x, ok := v.(uint32)
			if !ok {
				return nil, bad
			}
			b = binary.BigEndian.AppendUint32(b, x)
		case QualityType:
			x, ok := v.(Quality)
			if !ok {
				return nil, bad
			}
			if x&ValidityMask == ValidityReserved {
				return nil, fmt.Errorf("sv: member %d: the formerly reserved validity is not sent (C.3.5)", i+1)
			}
			b = binary.BigEndian.AppendUint32(b, uint32(x))
		}
	}
	return b, nil
}

func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// Quality is an IEC 61850-7-2 quality in the 32-bit form of Table 21.
// Table 21 numbers bits as Table 15 numbers a BITSTRING (bit 0 the most
// significant), so bit number n is the mask 1<<(31-n): validity is in the
// two least significant bits and the example of Table 21 (validity
// invalid, failure and test) is 0x0842.
type Quality uint32

// Quality masks (Table 21).
const (
	ValidityMask         Quality = 0x3
	ValidityGood         Quality = 0x0 // bits 31-30: 0 0
	ValidityInvalid      Quality = 0x2 // bits 31-30: 0 1
	ValidityReserved     Quality = 0x1 // bits 31-30: 1 0, read as invalid (C.3.5)
	ValidityQuestionable Quality = 0x3 // bits 31-30: 1 1
	Overflow             Quality = 1 << 2
	OutOfRange           Quality = 1 << 3
	BadReference         Quality = 1 << 4
	Oscillatory          Quality = 1 << 5
	Failure              Quality = 1 << 6
	OldData              Quality = 1 << 7
	Inconsistent         Quality = 1 << 8
	Inaccurate           Quality = 1 << 9
	Substituted          Quality = 1 << 10 // source: 0 process, 1 substituted
	Test                 Quality = 1 << 11
	OperatorBlocked      Quality = 1 << 12
	// Defined covers the bits Table 21 assigns (31 to 19); the others
	// are not defined by 9-2 (F-1074).
	Defined Quality = 0x1FFF
)

// QualityBit is the mask of Table 21 bit number n (0..31).
func QualityBit(n int) Quality { return 1 << (31 - n) }

// Validity is the validity of a quality.
type Validity int

// Validity values.
const (
	Good Validity = iota
	Invalid
	Questionable
)

// String names the value.
func (v Validity) String() string { return [...]string{"good", "invalid", "questionable"}[v] }

// Validity reads bits 31-30; the formerly reserved value is invalid
// (Table 21 footnote, C.3.5).
func (q Quality) Validity() Validity {
	switch q & ValidityMask {
	case ValidityGood:
		return Good
	case ValidityQuestionable:
		return Questionable
	}
	return Invalid
}

// Undefined is the bits Table 21 does not assign.
func (q Quality) Undefined() Quality { return q &^ Defined }

// String lists validity and the set flags.
func (q Quality) String() string {
	s := []string{q.Validity().String()}
	if q&ValidityMask == ValidityReserved {
		s[0] += "(reserved)"
	}
	for _, f := range []struct {
		m Quality
		n string
	}{{Overflow, "overflow"}, {OutOfRange, "outOfRange"}, {BadReference, "badReference"}, {Oscillatory, "oscillatory"},
		{Failure, "failure"}, {OldData, "oldData"}, {Inconsistent, "inconsistent"}, {Inaccurate, "inaccurate"},
		{Substituted, "substituted"}, {Test, "test"}, {OperatorBlocked, "operatorBlocked"}} {
		if q&f.m != 0 {
			s = append(s, f.n)
		}
	}
	if u := q.Undefined(); u != 0 {
		s = append(s, fmt.Sprintf("undefined=%#x", uint32(u)))
	}
	return strings.Join(s, ",")
}

// ParseType reads a Table 15 type name (case, spaces and underscores
// ignored), or "Quality" for the Table 21 quality.
func ParseType(name string) (Type, error) {
	norm := func(s string) string {
		return strings.ToUpper(strings.NewReplacer(" ", "", "_", "", "-", "").Replace(s))
	}
	n := norm(name)
	for t, i := range typeInfo {
		if norm(i.name) == n {
			return t, nil
		}
	}
	return 0, fmt.Errorf("sv: %q is not a basic type of Table 15", name)
}

// Numeric reports whether values of the type are numbers (integers,
// enumerations and FLOAT32).
func (t Type) Numeric() bool {
	switch t {
	case Int8, Int16, Int32, Int64, Int8U, Int16U, Int32U, Float32, Enumerated, CodedEnum:
		return true
	}
	return false
}
