package sv

import (
	"bytes"
	"math"
	"testing"
	"time"
)

func fullASDU(cnt uint16) ASDU {
	ds, rate, mod := "IED1MU/LLN0$PhsMeas1", uint16(80), SmpPerPeriod
	rt := Timestamp{Seconds: 0x5E5C0000, Fraction: 0x800000, Quality: 0x0A}
	gm := [8]byte{0x00, 0x1B, 0x19, 0xFF, 0xFE, 0x00, 0x00, 0x01}
	return ASDU{SvID: "4000", DatSet: &ds, SmpCnt: cnt, ConfRev: 1, RefrTm: &rt, SmpSynch: SynchGlobal, SmpRate: &rate,
		Sample: bytes.Repeat([]byte{0, 0, 0, 1, 0, 0, 0, 0}, 8), SmpMod: &mod, GmIdentity: &gm}
}

// tags walks the savPdu and lists identifier octets in order.
func tags(t *testing.T, b []byte) []byte {
	t.Helper()
	var out []byte
	var walk func([]byte, int)
	walk = func(b []byte, depth int) {
		es, err := readAll(b)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			out = append(out, e.first())
			// savPdu, asdu and each ASDU are walked into.
			if e.first() == 0x60 || e.first() == 0xA2 || e.first() == 0x30 {
				walk(e.val, depth+1)
			}
		}
	}
	walk(b, 0)
	return out
}

// Covers: SIG-IPE-2086, SIG-IPE-2087, SIG-IPE-2096
func TestFigureA6Structure(t *testing.T) {
	// Figure A.6: savPdu 60 with noASDU 80 = 4, security 81, asdu A2 and
	// four ASDUs 30 each holding 80 to 89 in order with the fixed sizes
	// L(2) L(4) L(1) L(2) L(2) L(8).
	sec := []byte{0x81, 0x02, 0xAB, 0xCD}
	p := &SavPDU{Security: sec, ASDUs: []ASDU{fullASDU(0), fullASDU(1), fullASDU(2), fullASDU(3)}}
	b, err := EncodePDU(p)
	if err != nil {
		t.Fatal(err)
	}
	asdu := []byte{0x30, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89}
	want := append([]byte{0x60, 0x80, 0x81, 0xA2}, bytes.Repeat(asdu, 4)...)
	if got := tags(t, b); !bytes.Equal(got, want) {
		t.Fatalf("tags % X\nwant % X", got, want)
	}
	if top := mustTLV(t, b); !bytes.Equal(mustTLV(t, top.val).raw, []byte{0x80, 0x01, 0x04}) {
		t.Errorf("noASDU = % X", mustTLV(t, top.val).raw)
	}
	got, err := DecodePDU(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Security, sec) || len(got.ASDUs) != 4 {
		t.Fatalf("decoded %+v", got)
	}
	// 8.5.1: the oldest samples first.
	for i, a := range got.ASDUs {
		if a.SmpCnt != uint16(i) || *a.SmpRate != 80 || *a.SmpMod != SmpPerPeriod || a.GmIdentity[1] != 0x1B || *a.RefrTm != *fullASDU(0).RefrTm || *a.DatSet != "IED1MU/LLN0$PhsMeas1" {
			t.Errorf("ASDU %d = %+v", i, a)
		}
	}
	// The field sizes of Table 14.
	e, _, _ := readTLV(b)
	kids, _ := readAll(e.val)
	seq, _ := readAll(kids[2].val)
	fields, _ := readAll(seq[0].val)
	for _, c := range []struct {
		tag  byte
		size int
	}{{0x82, 2}, {0x83, 4}, {0x84, 8}, {0x85, 1}, {0x86, 2}, {0x88, 2}, {0x89, 8}} {
		for _, f := range fields {
			if f.first() == c.tag && len(f.val) != c.size {
				t.Errorf("tag %X has %d octets, want %d", c.tag, len(f.val), c.size)
			}
		}
	}
	// The security element also round-trips in its constructed form
	// (F-1071).
	p.Security = []byte{0xA1, 0x04, 0xA0, 0x02, 0x80, 0x00}
	b, _ = EncodePDU(p)
	if got, err = DecodePDU(b); err != nil || !bytes.Equal(got.Security, p.Security) {
		t.Errorf("constructed security: %v", err)
	}
}

// Covers: SIG-IPE-2086
func TestSavPduGrammar(t *testing.T) {
	good, _ := EncodePDU(&SavPDU{ASDUs: []ASDU{leASDU()}})
	a := unhex(t, "30 1D 80 04 34303030 82 02 000A 83 04 00000001 85 01 02 87 08 000003E8 00000842")
	cases := map[string][]byte{
		"noASDU 0":          append(unhex(t, "60 24 80 01 00 A2 1F"), a...),
		"noASDU 2 for one":  append(unhex(t, "60 24 80 01 02 A2 1F"), a...),
		"noASDU negative":   append(unhex(t, "60 24 80 01 FF A2 1F"), a...),
		"noASDU padded":     append(unhex(t, "60 25 80 02 0001 A2 1F"), a...),
		"no noASDU":         append(unhex(t, "60 21 A2 1F"), a...),
		"no asdu":           unhex(t, "60 03 80 01 01"),
		"wrong tag":         append(unhex(t, "61 24 80 01 01 A2 1F"), a...),
		"indefinite length": append(unhex(t, "60 80 80 01 01 A2 1F"), a...),
		"security first":    append(unhex(t, "60 28 81 02 0000 80 01 01 A2 1F"), a...),
	}
	for name, b := range cases {
		if _, err := DecodePDU(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	if _, err := DecodePDU(good); err != nil {
		t.Fatal(err)
	}
	// "..." after asdu: an extension element is skipped.
	ext := append(unhex(t, "60 28 80 01 01 A2 1F"), append(a, 0x83, 0x02, 0xBE, 0xEF)...)
	if p, err := DecodePDU(ext); err != nil || len(p.ASDUs) != 1 {
		t.Errorf("savPdu extension: %v", err)
	}
	// noASDU of 128 and more takes the two-octet form with a leading 0.
	if !bytes.Equal(berUint(128), []byte{0, 0x80}) || !bytes.Equal(berUint(65535), []byte{0, 0xFF, 0xFF}) {
		t.Error("berUint")
	}
}

// Covers: SIG-IPE-2087, SIG-IPE-2088
func TestASDUComponents(t *testing.T) {
	wrap := func(body string) []byte {
		b := unhex(t, body)
		return append([]byte{0x30, byte(len(b))}, b...)
	}
	bad := map[string]string{
		"smpCnt 1 octet":     "80 01 41 82 01 0A 83 04 00000001 85 01 02 87 00",
		"smpCnt 4 octets":    "80 01 41 82 04 0000000A 83 04 00000001 85 01 02 87 00",
		"confRev 2 octets":   "80 01 41 82 02 000A 83 02 0001 85 01 02 87 00",
		"smpSynch 2":         "80 01 41 82 02 000A 83 04 00000001 85 02 0002 87 00",
		"refrTm 7":           "80 01 41 82 02 000A 83 04 00000001 84 07 00000000000000 85 01 02 87 00",
		"smpRate 1":          "80 01 41 82 02 000A 83 04 00000001 85 01 02 86 01 50 87 00",
		"smpMod 1":           "80 01 41 82 02 000A 83 04 00000001 85 01 02 87 00 88 01 00",
		"gmIdentity 6":       "80 01 41 82 02 000A 83 04 00000001 85 01 02 87 00 89 06 000000000000",
		"no svID":            "82 02 000A 83 04 00000001 85 01 02 87 00",
		"no smpCnt":          "80 01 41 83 04 00000001 85 01 02 87 00",
		"no confRev":         "80 01 41 82 02 000A 85 01 02 87 00",
		"no smpSynch":        "80 01 41 82 02 000A 83 04 00000001 87 00",
		"no sample":          "80 01 41 82 02 000A 83 04 00000001 85 01 02",
		"out of order":       "80 01 41 83 04 00000001 82 02 000A 85 01 02 87 00",
		"repeated":           "80 01 41 82 02 000A 82 02 000A 83 04 00000001 85 01 02 87 00",
		"empty svID":         "80 00 82 02 000A 83 04 00000001 85 01 02 87 00",
		"svID control char":  "80 01 07 82 02 000A 83 04 00000001 85 01 02 87 00",
		"sample constructed": "80 01 41 82 02 000A 83 04 00000001 85 01 02 A7 00",
	}
	for name, body := range bad {
		if _, err := decodeASDU(mustTLV(t, wrap(body))); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	// Optional components absent, and an extension after gmIdentity.
	a, err := decodeASDU(mustTLV(t, wrap("80 01 41 82 02 000A 83 04 00000001 85 01 00 87 00 8A 01 FF")))
	if err != nil || a.SvID != "A" || a.DatSet != nil || a.SmpRate != nil {
		t.Errorf("minimal ASDU = %+v, %v", a, err)
	}
	// VisString129: 129 characters are taken, 130 are not.
	long := leASDU()
	long.SvID = string(bytes.Repeat([]byte{'x'}, 129))
	if _, err := encodeASDU(long); err != nil {
		t.Errorf("svID of 129: %v", err)
	}
	long.SvID += "x"
	if _, err := encodeASDU(long); err == nil {
		t.Error("svID of 130 was encoded")
	}
	if RecommendedMsvID(0x4001) != "4001" {
		t.Error("RecommendedMsvID")
	}
}

func mustTLV(t *testing.T, b []byte) tlv {
	t.Helper()
	e, _, err := readTLV(b)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// Covers: SIG-IPE-2089
func TestBasicTypes(t *testing.T) {
	types := []Type{Boolean, Int8, Int16, Int32, Int64, Int8U, Int16U, Int32U, Float32, Enumerated, CodedEnum,
		OctetString, VisibleString, UnicodeString, ObjectName, ObjectReference, TimestampType, EntryTime, EntryID, Currency, BitString, QualityType}
	sizes := []int{1, 1, 2, 4, 8, 1, 2, 4, 4, 4, 4, 20, 35, 20, 20, 20, 8, 6, 8, 4, 4, 4}
	for i, ty := range types {
		if ty.Size() != sizes[i] {
			t.Errorf("%v size %d, want %d (Table 15)", ty, ty.Size(), sizes[i])
		}
	}
	ts := Timestamp{Seconds: 1, Fraction: 2, Quality: 3}
	vals := []any{true, int64(-2), int64(-300), int64(-70000), int64(math.MinInt64), uint64(255), uint64(65535), uint64(math.MaxUint32),
		float32(1.5), int64(-1), uint64(7), "oct", "LD0/LLN0.Mod.stVal", "unicode é", "Name", "LD0/LLN0", ts,
		[]byte{1, 2, 3, 4, 5, 6}, []byte{1, 2, 3, 4, 5, 6, 7, 8}, "INR", BitStringBit(0) | BitStringBit(31), Quality(0x0842)}
	b, err := EncodeSample(types, vals)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := SampleSize(types)
	if len(b) != n || n != 184 {
		t.Fatalf("sample of %d octets, size %d", len(b), n)
	}
	got, err := DecodeSample(types, b)
	if err != nil {
		t.Fatal(err)
	}
	for i := range vals {
		if bv, ok := vals[i].([]byte); ok {
			if !bytes.Equal(bv, got[i].([]byte)) {
				t.Errorf("member %d: %v", i, got[i])
			}
		} else if got[i] != vals[i] {
			t.Errorf("member %d (%v): %v (%T), want %v", i, types[i], got[i], got[i], vals[i])
		}
	}
	// Big-endian: INT16 -300 is FE D4; FLOAT32 1.5 is 3F C0 00 00;
	// BITSTRING bits 0 and 31 are 80 00 00 01.
	if !bytes.Equal(b[2:4], []byte{0xFE, 0xD4}) || !bytes.Equal(b[23:27], []byte{0x3F, 0xC0, 0, 0}) || !bytes.Equal(b[176:180], []byte{0x80, 0, 0, 1}) {
		t.Errorf("octets % X", b)
	}
	// BOOLEAN: 0 is FALSE, anything else TRUE.
	if v, _ := DecodeSample([]Type{Boolean, Boolean}, []byte{0, 0x05}); v[0] != false || v[1] != true {
		t.Errorf("BOOLEAN = %v", v)
	}
	// Text: null terminated within the size; a full field without NUL
	// is read whole (F-1083).
	full := bytes.Repeat([]byte{'a'}, 20)
	if v, _ := DecodeSample([]Type{ObjectName}, full); v[0] != string(full) {
		t.Error("full text field")
	}
	for name, c := range map[string]struct {
		ty Type
		v  any
	}{
		"INT8 128": {Int8, 128}, "INT16U -1": {Int16U, -1}, "INT32U 2^32": {Int32U, int64(1) << 32},
		"text 20": {ObjectName, string(full)}, "non-ASCII": {VisibleString, "é"}, "bool int": {Boolean, 1},
		"reserved validity": {QualityType, Quality(1)}, "EntryID 7": {EntryID, make([]byte, 7)},
	} {
		if _, err := EncodeSample([]Type{c.ty}, []any{c.v}); err == nil {
			t.Errorf("%s encoded", name)
		}
	}
	if _, err := DecodeSample([]Type{Int32}, []byte{0, 0, 0}); err == nil {
		t.Error("short sample decoded")
	}
	if n, _ := SampleSize(LE); n != 64 {
		t.Errorf("LE sample %d", n)
	}
}

// Covers: SIG-IPE-2090
func TestQualityTable21(t *testing.T) {
	q := Quality(0x0842)
	if q.Validity() != Invalid || q&Failure == 0 || q&Test == 0 || q.String() != "invalid,failure,test" {
		t.Errorf("0x0842 = %v", q)
	}
	for n, m := range map[int]Quality{29: Overflow, 28: OutOfRange, 27: BadReference, 26: Oscillatory, 25: Failure,
		24: OldData, 23: Inconsistent, 22: Inaccurate, 21: Substituted, 20: Test, 19: OperatorBlocked} {
		if QualityBit(n) != m {
			t.Errorf("bit %d = %#x, want %#x", n, QualityBit(n), m)
		}
	}
	// Bits 31-30: 00 good, 01 invalid, 10 formerly reserved (invalid), 11
	// questionable.
	if QualityBit(30) != ValidityInvalid || QualityBit(31) != ValidityReserved {
		t.Error("validity bits")
	}
	for v, want := range map[Quality]Validity{0: Good, 2: Invalid, 1: Invalid, 3: Questionable} {
		if v.Validity() != want {
			t.Errorf("validity %d = %v", v, v.Validity())
		}
	}
	if Quality(1).String() != "invalid(reserved)" || Quality(0x2000).String() != "good,undefined=0x2000" {
		t.Errorf("strings %q %q", Quality(1), Quality(0x2000))
	}
}

// Covers: SIG-IPE-2091
func TestSmpSynchValues(t *testing.T) {
	for v, want := range map[uint8]SynchClass{0: ClassInternal, 1: ClassLocal, 2: ClassGlobal, 3: ClassReserved, 4: ClassReserved,
		5: ClassLocal, 100: ClassLocal, 254: ClassLocal, 255: ClassReserved} {
		if got := ClassifySynch(v); got != want {
			t.Errorf("smpSynch %d = %v, want %v", v, got, want)
		}
	}
	// refrTm and gmIdentity: 8 octets, network order.
	ts := TimestampOf(time.Date(2020, 2, 1, 0, 0, 0, 500_000_000, time.UTC), 0x0A)
	if !bytes.Equal(ts.Bytes(), []byte{0x5E, 0x34, 0xBF, 0x80, 0x80, 0, 0, 0x0A}) || !ts.Time().Equal(time.Date(2020, 2, 1, 0, 0, 0, 500_000_000, time.UTC)) {
		t.Errorf("timestamp % X %v", ts.Bytes(), ts.Time())
	}
}

// Covers: SIG-IPE-2089
func TestParseType(t *testing.T) {
	for name, want := range map[string]Type{"BOOLEAN": Boolean, "int32": Int32, "INT16U": Int16U, "Float32": Float32,
		"CODED ENUM": CodedEnum, "coded_enum": CodedEnum, "VISIBLE STRING": VisibleString, "ObjectReference": ObjectReference,
		"Timestamp": TimestampType, "BITSTRING": BitString, "Quality": QualityType, "EntryTime": EntryTime} {
		if got, err := ParseType(name); err != nil || got != want {
			t.Errorf("ParseType(%q) = %v, %v", name, got, err)
		}
	}
	if _, err := ParseType("INT128"); err == nil {
		t.Error("INT128 parsed")
	}
	if !Float32.Numeric() || !CodedEnum.Numeric() || QualityType.Numeric() || Boolean.Numeric() {
		t.Error("Numeric")
	}
}
