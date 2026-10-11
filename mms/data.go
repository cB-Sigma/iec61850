package mms

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

// Kind is an MMS Data alternative; the value is its context tag number
// (ISO 9506-2:2003 14.4.2; utc-time [17] is the IEC 61850-8-1 addition).
type Kind int

// Data alternatives.
const (
	KArray      Kind = 1
	KStructure  Kind = 2
	KBool       Kind = 3
	KBitString  Kind = 4
	KInt        Kind = 5
	KUint       Kind = 6
	KFloat      Kind = 7
	KOctets     Kind = 9
	KVisible    Kind = 10
	KGenTime    Kind = 11
	KBinaryTime Kind = 12
	KBCD        Kind = 13
	KBoolArray  Kind = 14 // decoded into an array of booleans
	KObjID      Kind = 15
	KMMSString  Kind = 16
	KUTCTime    Kind = 17
)

// String names the value.
func (k Kind) String() string {
	switch k {
	case KArray:
		return "array"
	case KStructure:
		return "structure"
	case KBool:
		return "boolean"
	case KBitString:
		return "bit-string"
	case KInt:
		return "integer"
	case KUint:
		return "unsigned"
	case KFloat:
		return "floating-point"
	case KOctets:
		return "octet-string"
	case KVisible:
		return "visible-string"
	case KGenTime:
		return "generalized-time"
	case KBinaryTime:
		return "binary-time"
	case KBCD:
		return "bcd"
	case KBoolArray:
		return "boolean-array"
	case KObjID:
		return "object-identifier"
	case KMMSString:
		return "mms-string"
	case KUTCTime:
		return "utc-time"
	}
	return fmt.Sprintf("data-%d", int(k))
}

// Data is an MMS Data value.
type Data struct {
	Kind  Kind
	Elems []Data // array, structure
	Bool  bool
	Int   int64   // integer
	Uint  uint64  // unsigned, bcd
	Float float64 // floating-point
	// Double marks a floating-point value sent in 64 bits.
	Double bool
	Bits   BitString // bit-string
	Bytes  []byte    // octet-string, binary-time, generalized-time
	Str    string    // visible-string, mms-string, object identifier (dotted)
	Time   UTCTime   // utc-time
}

// UTCTime is the IEC 61850 TimeStamp: seconds and fraction since the Unix
// epoch, and the time quality octet.
type UTCTime struct {
	T       time.Time
	Quality byte
}

// Time quality bits (IEC 61850-8-1 TimeStamp, last octet).
const (
	TimeLeapSecondKnown      = 0x80
	TimeClockFailure         = 0x40
	TimeClockNotSynced       = 0x20
	TimeAccuracyMask    byte = 0x1f
)

// Structure is an MMS structure of the elements (the constructors
// below make the other kinds).
func Structure(e ...Data) Data { return Data{Kind: KStructure, Elems: e} }

// Array is an MMS array of the elements.
func Array(e ...Data) Data { return Data{Kind: KArray, Elems: e} }

// Boolean is an MMS boolean.
func Boolean(v bool) Data { return Data{Kind: KBool, Bool: v} }

// Integer is an MMS integer.
func Integer(v int64) Data { return Data{Kind: KInt, Int: v} }

// Unsigned is an MMS unsigned integer.
func Unsigned(v uint64) Data { return Data{Kind: KUint, Uint: v} }

// Float32 is an MMS floating-point value of 32 bits.
func Float32(v float64) Data { return Data{Kind: KFloat, Float: v} }

// Float64 is an MMS floating-point value of 64 bits.
func Float64(v float64) Data { return Data{Kind: KFloat, Float: v, Double: true} }

// Visible is an MMS visible string.
func Visible(s string) Data { return Data{Kind: KVisible, Str: s} }

// MMSString is an MMS string (UTF-8).
func MMSString(s string) Data { return Data{Kind: KMMSString, Str: s} }

// Octets is an MMS octet string.
func Octets(b []byte) Data { return Data{Kind: KOctets, Bytes: b} }

// Bits is an MMS bit string.
func Bits(b BitString) Data { return Data{Kind: KBitString, Bits: b} }

// Timestamp is an MMS UTC time with time quality 0x0A (10 bits of
// accuracy, clock synchronised).
func Timestamp(t time.Time) Data { return Data{Kind: KUTCTime, Time: UTCTime{T: t, Quality: 0x0a}} }

// Encode encodes d as an MMS Data element.
func (d Data) Encode() []byte {
	switch d.Kind {
	case KArray, KStructure:
		parts := make([][]byte, len(d.Elems))
		for i, e := range d.Elems {
			parts[i] = e.Encode()
		}
		return T(0xa0|byte(d.Kind), parts...)
	case KBool:
		return Bool(0x83, d.Bool)
	case KBitString:
		return T(0x84, d.Bits.Contents())
	case KInt:
		return Int(0x85, d.Int)
	case KUint:
		return Uint(0x86, d.Uint)
	case KBCD:
		return Uint(0x8d, d.Uint)
	case KBoolArray:
		return T(0x8e, d.Bits.Contents())
	case KObjID:
		return T(0x8f, OID(d.Str))
	case KFloat:
		if d.Double {
			return T(0x87, float64Bytes(d.Float))
		}
		return T(0x87, float32Bytes(d.Float))
	case KOctets, KBinaryTime, KGenTime:
		return T(0x80|byte(d.Kind), d.Bytes)
	case KVisible, KMMSString:
		return T(0x80|byte(d.Kind), []byte(d.Str))
	case KUTCTime:
		return T(0x91, d.Time.Encode())
	}
	panic(fmt.Sprintf("mms: cannot encode %s", d.Kind))
}

// Encode is the 8-octet UtcTime form.
func (u UTCTime) Encode() []byte {
	b := make([]byte, 8)
	if u.T.IsZero() {
		return b
	}
	sec := u.T.Unix()
	binary.BigEndian.PutUint32(b, uint32(sec))
	frac := uint32(uint64(u.T.Nanosecond()) * (1 << 24) / 1e9)
	b[4], b[5], b[6] = byte(frac>>16), byte(frac>>8), byte(frac)
	b[7] = u.Quality
	return b
}

// DecodeUTCTime reads the 8-octet UtcTime form.
func DecodeUTCTime(b []byte) (UTCTime, error) {
	if len(b) != 8 {
		return UTCTime{}, fmt.Errorf("mms: a utc-time of %d octets", len(b))
	}
	sec := binary.BigEndian.Uint32(b)
	frac := uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6])
	if sec == 0 && frac == 0 {
		return UTCTime{Quality: b[7]}, nil
	}
	ns := int64(uint64(frac) * 1e9 >> 24)
	return UTCTime{T: time.Unix(int64(sec), ns).UTC(), Quality: b[7]}, nil
}

// BinaryTime is the 6-octet TimeOfDay form (milliseconds since midnight,
// days since 1984-01-01) used for TimeOfEntry.
func BinaryTime(t time.Time) Data {
	t = t.UTC()
	epoch := time.Date(1984, 1, 1, 0, 0, 0, 0, time.UTC)
	days := int(t.Sub(epoch).Hours() / 24)
	mid := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	ms := uint32(t.Sub(mid).Milliseconds())
	b := make([]byte, 6)
	binary.BigEndian.PutUint32(b, ms)
	binary.BigEndian.PutUint16(b[4:], uint16(days))
	return Data{Kind: KBinaryTime, Bytes: b}
}

// DecodeBinaryTime reads a 4- or 6-octet binary-time.
func DecodeBinaryTime(b []byte) (time.Time, error) {
	if len(b) != 6 && len(b) != 4 {
		return time.Time{}, fmt.Errorf("mms: a binary-time of %d octets", len(b))
	}
	ms := binary.BigEndian.Uint32(b)
	days := 0
	if len(b) == 6 {
		days = int(binary.BigEndian.Uint16(b[4:]))
	}
	return time.Date(1984, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, days).Add(time.Duration(ms) * time.Millisecond), nil
}

// DecodeData decodes one MMS Data element.
func DecodeData(e Elem) (Data, error) {
	if e.Tag&0xc0 != 0x80 {
		return Data{}, fmt.Errorf("mms: data with tag %#x", e.Tag)
	}
	k := Kind(e.Num)
	d := Data{Kind: k}
	var err error
	switch k {
	case KArray, KStructure:
		kids, err := e.Children()
		if err != nil {
			return Data{}, err
		}
		d.Elems = make([]Data, len(kids))
		for i, c := range kids {
			if d.Elems[i], err = DecodeData(c); err != nil {
				return Data{}, err
			}
		}
	case KBool:
		if len(e.Val) != 1 {
			return Data{}, errors.New("mms: a boolean of the wrong length")
		}
		d.Bool = e.Val[0] != 0
	case KBitString:
		d.Bits, err = DecodeBitString(e.Val)
	case KInt:
		d.Int, err = DecodeInt(e.Val)
	case KUint:
		d.Uint, err = DecodeUint(e.Val)
	case KFloat:
		d.Float, d.Double, err = DecodeFloatingPoint(e.Val)
	case KBCD:
		d.Uint, err = DecodeUint(e.Val)
	case KBoolArray:
		// A sender's alternative to an array of booleans, with no
		// difference in meaning (14.4.2.1): read as the array.
		var b BitString
		if b, err = DecodeBitString(e.Val); err != nil {
			return Data{}, err
		}
		d.Kind = KArray
		for i := 0; i < b.NBits; i++ {
			d.Elems = append(d.Elems, Boolean(b.Get(i)))
		}
	case KObjID:
		d.Str = DecodeOID(e.Val)
	case KOctets, KBinaryTime, KGenTime:
		d.Bytes = append([]byte(nil), e.Val...)
	case KVisible, KMMSString:
		d.Str = string(e.Val)
	case KUTCTime:
		d.Time, err = DecodeUTCTime(e.Val)
	default:
		return Data{}, fmt.Errorf("mms: data alternative %d is not supported", e.Num)
	}
	return d, err
}

// DecodeFloatingPoint reads a FloatingPoint (ISO 9506-2:2003 14.4.2.2):
// the exponent width octet, then sign, exponent and fraction bits. The
// IEEE 754 single (8, 4 octets) and double (11, 8 octets) forms are read
// directly; other widths up to 8 value octets are converted, rounding the
// fraction to the nearest float64. double reports a value wider than 32
// bits.
func DecodeFloatingPoint(v []byte) (f float64, double bool, err error) {
	if len(v) < 2 {
		return 0, false, errors.New("mms: a floating-point value shorter than two octets")
	}
	n, rest := int(v[0]), v[1:]
	switch {
	case n == 8 && len(rest) == 4:
		return float64(math.Float32frombits(binary.BigEndian.Uint32(rest))), false, nil
	case n == 11 && len(rest) == 8:
		return math.Float64frombits(binary.BigEndian.Uint64(rest)), true, nil
	}
	total := 8 * len(rest)
	if len(rest) > 8 || n < 1 || n > total-1 || n > 30 {
		return 0, false, fmt.Errorf("mms: a floating-point value of exponent width %d in %d octets is not supported", n, len(rest))
	}
	var raw uint64
	for _, c := range rest {
		raw = raw<<8 | uint64(c)
	}
	fb := total - 1 - n
	sign := raw >> (total - 1) & 1
	exp := int(raw >> fb & (1<<n - 1))
	frac := raw & (1<<fb - 1)
	bias := 1<<(n-1) - 1
	switch {
	case exp == 1<<n-1 && frac == 0:
		f = math.Inf(1)
	case exp == 1<<n-1:
		f = math.NaN()
	case exp == 0:
		f = math.Ldexp(float64(frac), 1-bias-fb)
	default:
		f = math.Ldexp(float64(frac|1<<fb), exp-bias-fb)
	}
	if sign == 1 {
		f = -f
	}
	return f, total > 32, nil
}

// ---- type descriptions ------------------------------------------------------

// TypeSpec is an MMS TypeDescription.
type TypeSpec struct {
	Kind Kind
	// Size is the bit size of integers, the length of strings (negative
	// for variable length), or the floating-point format width.
	Size       int
	Elements   int       // array
	Elem       *TypeSpec // array
	Components []Component
}

// Component is a named structure member.
type Component struct {
	Name string
	Type TypeSpec
}

// Find returns the named component of a structure.
func (t TypeSpec) Find(name string) (TypeSpec, int, bool) {
	for i, c := range t.Components {
		if c.Name == name {
			return c.Type, i, true
		}
	}
	return TypeSpec{}, -1, false
}

// Encode encodes t as a TypeDescription element.
func (t TypeSpec) Encode() []byte {
	switch t.Kind {
	case KArray:
		var el []byte
		if t.Elem != nil {
			el = t.Elem.Encode()
		}
		return T(0xa1, Uint(0x81, uint64(t.Elements)), T(0xa2, el))
	case KStructure:
		comps := make([][]byte, len(t.Components))
		for i, c := range t.Components {
			comps[i] = T(0x30, Str(0x80, c.Name), T(0xa1, c.Type.Encode()))
		}
		return T(0xa2, T(0xa1, comps...))
	case KBool:
		return T(0x83)
	case KFloat:
		w, e := 32, 8
		if t.Size == 64 {
			w, e = 64, 11
		}
		return T(0xa7, Uint(0x02, uint64(w)), Uint(0x02, uint64(e)))
	case KUTCTime, KGenTime, KObjID:
		return T(0x80 | byte(t.Kind)) // NULL
	case KBinaryTime:
		return Bool(0x8c, t.Size == 6)
	case KBCD, KInt, KUint:
		return Uint(0x80|byte(t.Kind), uint64(t.Size)) // Unsigned8
	default:
		return Int(0x80|byte(t.Kind), int64(t.Size))
	}
}

// DecodeTypeSpec decodes a TypeDescription element.
func DecodeTypeSpec(e Elem) (TypeSpec, error) {
	if e.Tag&0xc0 != 0x80 {
		return TypeSpec{}, fmt.Errorf("mms: type description with tag %#x", e.Tag)
	}
	t := TypeSpec{Kind: Kind(e.Num)}
	switch t.Kind {
	case KArray:
		kids, err := e.Children()
		if err != nil {
			return t, err
		}
		for _, k := range kids {
			switch {
			case k.Context(1):
				n, _ := DecodeUint(k.Val)
				t.Elements = int(n)
			case k.Context(2):
				in, _, err := Parse(k.Val)
				if err != nil {
					return t, err
				}
				el, err := DecodeTypeSpec(in)
				if err != nil {
					return t, err
				}
				t.Elem = &el
			}
		}
	case KStructure:
		kids, err := e.Children()
		if err != nil {
			return t, err
		}
		for _, k := range kids {
			if !k.Context(1) {
				continue
			}
			comps, err := k.Children()
			if err != nil {
				return t, err
			}
			for _, c := range comps {
				parts, err := c.Children()
				if err != nil {
					return t, err
				}
				var comp Component
				for _, p := range parts {
					switch {
					case p.Context(0):
						comp.Name = string(p.Val)
					case p.Context(1):
						in, _, err := Parse(p.Val)
						if err != nil {
							return t, err
						}
						if comp.Type, err = DecodeTypeSpec(in); err != nil {
							return t, err
						}
					}
				}
				t.Components = append(t.Components, comp)
			}
		}
	case KFloat:
		kids, _ := e.Children()
		if len(kids) == 2 {
			w, _ := DecodeUint(kids[0].Val)
			t.Size = int(w)
		}
	case KBool, KUTCTime, KGenTime, KObjID:
	case KMMSString:
		// mMSString [16] Integer32 is printed without IMPLICIT; deployed
		// peers send it implicit (findings F-691): both are read.
		b := e.Val
		if e.Constructed() {
			in, _, err := Parse(e.Val)
			if err != nil {
				return t, err
			}
			b = in.Val
		}
		n, err := DecodeInt(b)
		if err != nil {
			return t, err
		}
		t.Size = int(n)
	case KBinaryTime:
		if len(e.Val) == 1 && e.Val[0] != 0 {
			t.Size = 6
		} else {
			t.Size = 4
		}
	default:
		n, err := DecodeInt(e.Val)
		if err != nil {
			return t, err
		}
		t.Size = int(n)
	}
	return t, nil
}

// TypeOf derives the type of a value (used by servers that hold values).
func TypeOf(d Data) TypeSpec {
	t := TypeSpec{Kind: d.Kind}
	switch d.Kind {
	case KArray:
		t.Elements = len(d.Elems)
		if len(d.Elems) > 0 {
			el := TypeOf(d.Elems[0])
			t.Elem = &el
		}
	case KInt, KUint:
		t.Size = 32
	case KFloat:
		t.Size = 32
		if d.Double {
			t.Size = 64
		}
	case KBitString:
		t.Size = d.Bits.NBits
	case KOctets:
		t.Size = -64
	case KVisible, KMMSString:
		t.Size = -255
	case KBinaryTime:
		t.Size = len(d.Bytes)
	}
	return t
}
