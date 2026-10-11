package mms

import (
	"bytes"
	"encoding/hex"
	"math"
	"net"
	"testing"
	"time"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Covers: SIG-IPE-158
func TestMMSBERPrimitives(t *testing.T) {
	for _, tc := range []struct {
		got  []byte
		want string
	}{
		{Int(0x02, 0), "020100"},
		{Int(0x02, 127), "02017f"},
		{Int(0x02, 128), "02020080"},
		{Int(0x02, -129), "0202ff7f"},
		{Uint(0x86, 255), "860200ff"},
		{Bool(0x83, true), "8301ff"},
		{T(0x06, OID("1.0.9506.2.3")), "060528ca220203"},
		{T(0x06, OID("2.2.1.0.1")), "060452010001"},
		{T(0x30, make([]byte, 200))[:3], "3081c8"},
		{T(0x30, make([]byte, 300))[:4], "3082012c"},
		{TH(0xa0, 72), "bf4800"},
		{Float32(1.5).Encode(), "8705083fc00000"},
		{Float64(-2).Encode(), "87090bc000000000000000"},
		{Visible("LD0").Encode(), "8a034c4430"},
		{Structure(Boolean(false), Integer(-1)).Encode(), "a2068301008501ff"},
		{GetNameListRequest(ClassDomain, "", ""), "a109a003800109a1028000"},
		{GetNameListRequest(ClassNamedVariable, "LD0", "MMXU1"), "a113a003800100a1058103" + "4c4430" + "82054d4d585531"},
		{ReadRequest(VariableSpec{Vars: []ObjectName{DomainName("LD0", "X")}}), "a412a110a00e300ca00aa1081a034c44301a0158"},
		{WriteResponse([]error{nil, ErrObjectAccessDenied}), "a50581008001" + "03"},
		{ConfirmedErrorPDU(7, 7, 2), "a20a800107a205a0038701" + "02"},
	} {
		if g := hex.EncodeToString(tc.got); g != tc.want {
			t.Errorf("encoded %s, want %s", g, tc.want)
		}
	}
	e, rest, err := Parse(unhex(t, "bf48020102ff"))
	if err != nil || e.Num != 72 || !e.Constructed() || !bytes.Equal(e.Val, []byte{1, 2}) || len(rest) != 1 {
		t.Errorf("high tag parse = %+v %x %v", e, rest, err)
	}
	for _, bad := range []string{"30", "3005010203", "3080", "30850000000001", "1f"} {
		if _, _, err := Parse(unhex(t, bad)); err == nil {
			t.Errorf("Parse(%s) succeeded", bad)
		}
	}
	if s := DecodeOID(OID("1.0.9506.2.1")); s != "1.0.9506.2.1" {
		t.Errorf("OID round trip = %s", s)
	}
	for _, v := range []int64{0, 1, -1, 127, -128, 128, 1 << 40, math.MinInt64, math.MaxInt64} {
		if got, err := DecodeInt(IntBytes(v)); err != nil || got != v {
			t.Errorf("int %d round trip = %d, %v", v, got, err)
		}
	}
	if _, err := DecodeUint([]byte{0x80}); err == nil {
		t.Error("a negative unsigned value was accepted")
	}
	bs := NewBitString(13)
	bs.Set(1, true)
	bs.Set(12, true)
	if g := hex.EncodeToString(bs.Contents()); g != "034008" {
		t.Errorf("bit string = %s, want 034008", g)
	}
	back, err := DecodeBitString(bs.Contents())
	if err != nil || back.NBits != 13 || !back.Get(1) || !back.Get(12) || back.Get(0) {
		t.Errorf("bit string round trip = %+v %v", back, err)
	}
}

// Covers: SIG-IPE-158
func TestMMSDataAndTypes(t *testing.T) {
	ts := time.Date(2026, 9, 24, 10, 30, 15, 500_000_000, time.UTC)
	values := []Data{
		Boolean(true), Integer(-70000), Unsigned(1 << 33), Float32(49.75), Float64(math.Pi),
		Visible("CSWI1$CO$Pos"), MMSString("x"), Octets([]byte{1, 2, 3}), Bits(NewBitString(10)),
		Timestamp(ts), BinaryTime(ts),
		Structure(Array(Integer(1), Integer(2)), Structure(Boolean(false))),
	}
	for _, v := range values {
		e, _, err := Parse(v.Encode())
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeData(e)
		if err != nil {
			t.Fatalf("%s: %v", v.Kind, err)
		}
		if !bytes.Equal(got.Encode(), v.Encode()) {
			t.Errorf("%s round trip %x, want %x", v.Kind, got.Encode(), v.Encode())
		}
	}
	// UtcTime: seconds, 24-bit fraction, quality octet.
	u := UTCTime{T: time.Unix(0x5f5e1000, 500_000_000), Quality: TimeClockNotSynced | 10}
	if g := hex.EncodeToString(u.Encode()); g != "5f5e10008000002a" {
		t.Errorf("utc-time = %s", g)
	}
	back, _ := DecodeUTCTime(u.Encode())
	if !back.T.Equal(u.T) || back.Quality != u.Quality {
		t.Errorf("utc-time round trip = %v", back)
	}
	// TimeOfEntry: milliseconds of the day, days since 1984-01-01.
	bt := BinaryTime(time.Date(1984, 1, 2, 0, 0, 1, 0, time.UTC))
	if g := hex.EncodeToString(bt.Bytes); g != "000003e80001" {
		t.Errorf("binary-time = %s", g)
	}
	if tm, _ := DecodeBinaryTime(BinaryTime(ts).Bytes); !tm.Equal(ts) {
		t.Errorf("binary-time round trip = %v", tm)
	}
	typ := TypeSpec{Kind: KStructure, Components: []Component{
		{Name: "stVal", Type: TypeSpec{Kind: KBool}},
		{Name: "q", Type: TypeSpec{Kind: KBitString, Size: 13}},
		{Name: "t", Type: TypeSpec{Kind: KUTCTime}},
		{Name: "mag", Type: TypeSpec{Kind: KStructure, Components: []Component{{Name: "f", Type: TypeSpec{Kind: KFloat, Size: 32}}}}},
		{Name: "ar", Type: TypeSpec{Kind: KArray, Elements: 3, Elem: &TypeSpec{Kind: KInt, Size: 8}}},
		{Name: "d", Type: TypeSpec{Kind: KVisible, Size: -255}},
	}}
	e, _, err := Parse(typ.Encode())
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeTypeSpec(e)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Encode(), typ.Encode()) {
		t.Errorf("type round trip %x, want %x", got.Encode(), typ.Encode())
	}
	if ft, i, ok := got.Find("mag"); !ok || i != 3 || ft.Components[0].Type.Size != 32 {
		t.Errorf("Find(mag) = %+v %d %v", ft, i, ok)
	}
}

// Covers: SIG-IPE-158
func TestMMSTransportSegmentsAndSession(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ta, tb := newTransport(a), newTransport(b)
	ta.maxData = 125 // TPDU size 128
	big := bytes.Repeat([]byte("0123456789"), 2000)
	errc := make(chan error, 1)
	go func() { errc <- ta.writeTSDU(big) }()
	got, err := tb.readTSDU()
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("segmented TSDU: %d bytes, %v", len(got), err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	// Session parameters with the long length form and user data.
	ud := bytes.Repeat([]byte{0xab}, 300)
	s := spdu(spduConnect, connectItems(), sessParam(0xc1, ud))
	si, params, rest, err := parseSPDU(s)
	if err != nil || si != spduConnect || len(rest) != 0 || !bytes.Equal(sessUserData(params), ud) {
		t.Errorf("session connect round trip: si %x, %v", si, err)
	}
	if hex.EncodeToString(s[:2]) != "0dff" {
		t.Errorf("a long SPDU starts %x", s[:4])
	}
	// Presentation user data carries the PDU in its context.
	ctx, pdu, err := userDataPDU(pdv(ctxMMS, []byte{0x8b, 0}))
	if err != nil || ctx != ctxMMS || !bytes.Equal(pdu, []byte{0x8b, 0}) {
		t.Errorf("presentation data = %d %x %v", ctx, pdu, err)
	}
	// TPKT refuses a wrong version.
	c, d := net.Pipe()
	defer c.Close()
	defer d.Close()
	go func() { _, _ = c.Write([]byte{4, 0, 0, 8, 2, 0xf0, 0x80, 0}) }()
	if _, err := newTransport(d).readTPKT(); err == nil {
		t.Error("a TPKT version 4 packet was accepted")
	}
}

// Covers: SIG-IPE-158
func TestMMSAssociationFrames(t *testing.T) {
	p := Params{Password: "pw", RemoteAPTitle: "1.1.1.999.1", RemoteAEQual: 12, LocalAPTitle: "1.1.1.999", LocalAEQual: 12}.withDefaults()
	rq, err := aarq(p, InitiateRequest())
	if err != nil {
		t.Fatal(err)
	}
	cp := cpType(p, rq)
	ud, err := findUserData(cp)
	if err != nil {
		t.Fatal(err)
	}
	_, pdu, err := userDataPDU(ud)
	if err != nil {
		t.Fatal(err)
	}
	f, err := acseFields(pdu, 0x60)
	if err != nil {
		t.Fatal(err)
	}
	ctxName, _, _ := Parse(f[0xa1].Val)
	if DecodeOID(ctxName.Val) != oidMMSContext {
		t.Errorf("application context = %s", DecodeOID(ctxName.Val))
	}
	if mech := DecodeOID(f[0x8b].Val); mech != oidPasswordAut {
		t.Errorf("mechanism = %s", mech)
	}
	ini, err := externalMMS(f[0xbe])
	if err != nil || ini[0] != TagInitiateRequest {
		t.Errorf("initiate request in AARQ: %x %v", ini, err)
	}
	// The accept carries the AARE and the initiate response.
	cpa := cpaType([]byte{0, 0, 0, 1}, proposedContexts(cp), aare(ACSEAccepted, 0, InitiateResponse(), nil))
	ud, err = findUserData(cpa)
	if err != nil {
		t.Fatal(err)
	}
	_, pdu, _ = userDataPDU(ud)
	f, err = acseFields(pdu, 0x61)
	if err != nil {
		t.Fatal(err)
	}
	if ini, _ := externalMMS(f[0xbe]); len(ini) == 0 || ini[0] != TagInitiateResponse {
		t.Errorf("initiate response in AARE: %x", ini)
	}
}

// FuzzMMSDecode checks that no input makes the decoders panic.
// Covers: SIG-IPE-158
func FuzzMMSDecode(f *testing.F) {
	f.Add(Structure(Integer(1), Visible("x"), Bits(NewBitString(13))).Encode())
	f.Add(InformationReportPDU(VariableSpec{ListName: &ObjectName{Item: "RPT"}}, []AccessResult{{Data: Visible("r")}, {Err: ErrObjectUndefined}}))
	f.Add(TypeSpec{Kind: KStructure, Components: []Component{{Name: "a", Type: TypeSpec{Kind: KBool}}}}.Encode())
	rq, _ := aarq(Params{}.withDefaults(), InitiateRequest())
	f.Add(cpType(Params{}.withDefaults(), rq))
	f.Fuzz(func(t *testing.T, b []byte) {
		if e, _, err := Parse(b); err == nil {
			_, _ = DecodeData(e)
			_, _ = DecodeTypeSpec(e)
			_, _ = DecodeInformationReport(e)
			_, _ = DecodeVariableSpec(e)
			_, _ = DecodeConfirmedRequest(e)
			_, _, _ = decodeNameList(e)
			_, _ = decodeReadResponse(e)
			_ = decodeServiceError(e)
		}
		_, _ = findUserData(b)
		_, _, _ = userDataPDU(b)
		_, _, _, _ = parseSPDU(b)
		_ = sessUserData(b)
	})
}
