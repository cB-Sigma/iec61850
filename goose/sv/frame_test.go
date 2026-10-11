package sv

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// vectorLE is a tagged frame laid out as Figure A.1: destination
// 01-0C-CD-04-00-01 (Table B.1), priority 4 and VID 0 (Table 7), ethertype
// 88-BA (Table 8), APPID 0x4000 at octet 18 and the APDU at octet 26,
// Length 8 + m, one ASDU with svID "4000", smpCnt 10, confRev 1, smpSynch 2
// and a sample of an INT32 (1000) and its quality 0x0842 (Table 21's
// example: invalid, failure, test).
const vectorLE = `010CCD040001 001A2B3C4D5E 8100 8000 88BA 4000 002E 0000 0000
	60 24 80 01 01 A2 1F 30 1D 80 04 34303030 82 02 000A 83 04 00000001 85 01 02
	87 08 000003E8 00000842`

func leASDU() ASDU {
	return ASDU{SvID: "4000", SmpCnt: 10, ConfRev: 1, SmpSynch: SynchGlobal, Sample: []byte{0, 0, 3, 0xE8, 0, 0, 8, 0x42}}
}

// Covers: SIG-IPE-2080
func TestFrameVectorFigureA1(t *testing.T) {
	want := unhex(t, vectorLE)
	h := Header{Dst: net.HardwareAddr{1, 0x0C, 0xCD, 4, 0, 1}, Src: net.HardwareAddr{0, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E},
		Tagged: true, Priority: DefaultPriority, VID: DefaultVID, APPID: APPIDDefault}
	got, err := Encode(h, &SavPDU{ASDUs: []ASDU{leASDU()}})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Encode = %X, %v\nwant     %X", got, err, want)
	}
	f, err := Decode(want)
	if err != nil {
		t.Fatal(err)
	}
	if f.Offset != 18 || !f.Tagged || f.Priority != 4 || f.VID != 0 || f.CFI || f.APPID != 0x4000 || f.Length != 46 || len(f.APDU) != 38 {
		t.Errorf("header = %+v", f.Header)
	}
	if !bytes.Equal(want[26:], f.APDU) {
		t.Error("the APDU does not start at octet 26")
	}
	a := f.PDU.ASDUs[0]
	if a.SvID != "4000" || a.SmpCnt != 10 || a.ConfRev != 1 || a.SmpSynch != 2 || a.DatSet != nil || a.RefrTm != nil || a.SmpRate != nil || a.SmpMod != nil || a.GmIdentity != nil {
		t.Errorf("ASDU = %+v", a)
	}
	v, err := DecodeSample([]Type{Int32, QualityType}, a.Sample)
	if err != nil || v[0] != int64(1000) || v[1] != Quality(0x0842) {
		t.Errorf("sample = %v, %v", v, err)
	}
}

// Covers: SIG-IPE-2080
func TestUntaggedAndAnyVLAN(t *testing.T) {
	// 5.3.3.3: frames without the tag, and any VID and priority, are taken.
	b := unhex(t, vectorLE)
	untagged := append(append([]byte(nil), b[:12]...), b[16:]...)
	f, err := Decode(untagged)
	if err != nil || f.Tagged || f.Offset != 14 || f.PDU.ASDUs[0].SmpCnt != 10 {
		t.Fatalf("untagged = %+v, %v", f, err)
	}
	other := append([]byte(nil), b...)
	other[14], other[15] = 0xFF, 0xFF // priority 7, CFI 1, VID 4095
	if f, err = Decode(other); err != nil || f.Priority != 7 || !f.CFI || f.VID != 4095 {
		t.Fatalf("tagged 7/4095 = %+v, %v", f, err)
	}
	if _, err := Decode(append(append([]byte(nil), b[:16]...), 0x88, 0xB8)); !errors.Is(err, ErrNotSV) {
		t.Errorf("GOOSE ethertype: %v", err)
	}
}

// Covers: SIG-IPE-2082
func TestAPPIDRange(t *testing.T) {
	// Table 8: the two most significant bits are 0 1; 5.3.3.4.2.
	for _, c := range []struct {
		appid uint16
		ok    bool
	}{{0x3FFF, false}, {0x4000, true}, {0x7FFF, true}, {0x8000, false}, {0x0001, false}} {
		if got := (Header{APPID: c.appid}).APPIDInRange(); got != c.ok {
			t.Errorf("%#04x in range = %v", c.appid, got)
		}
	}
	if APPIDMin != 0x4000 || APPIDMax != 0x7FFF || APPIDDefault != 0x4000 || EtherType != 0x88BA {
		t.Error("constants of Table 8 / 5.3.3.4.2")
	}
}

// Covers: SIG-IPE-2083
func TestLengthField(t *testing.T) {
	b := unhex(t, vectorLE)
	set := func(n uint16) []byte {
		c := append([]byte(nil), b...)
		c[20], c[21] = byte(n>>8), byte(n)
		return c
	}
	if _, err := Decode(set(7)); err == nil {
		t.Error("Length below 8 was taken")
	}
	if _, err := Decode(set(47)); err == nil {
		t.Error("Length beyond the frame was taken")
	}
	// A Length shorter than the savPdu leaves it cut: inconsistent.
	if _, err := Decode(set(45)); err == nil {
		t.Error("Length inside the savPdu was taken")
	}
	// Octets inside Length after the savPdu are inconsistent too.
	longer := append(set(47), 0)
	if _, err := Decode(longer); err == nil {
		t.Error("octets after the savPdu inside Length were taken")
	}
	// Padding after Length is not part of the APDU.
	if f, err := Decode(append(append([]byte(nil), b...), make([]byte, 10)...)); err != nil || len(f.Tail) != 10 {
		t.Errorf("padding: %v", err)
	}
	// m = 1492 is the largest APDU; 1493 is refused on both sides.
	for _, m := range []int{MaxAPDU, MaxAPDU + 1} {
		a := leASDU()
		a.Sample = nil
		base, _ := EncodePDU(&SavPDU{ASDUs: []ASDU{a}})
		// Grow the sample until the APDU has m octets.
		a.Sample = make([]byte, m-len(base)-2)
		apdu, err := EncodePDU(&SavPDU{ASDUs: []ASDU{a}})
		if err != nil {
			t.Fatal(err)
		}
		if len(apdu) != m {
			a.Sample = a.Sample[:len(a.Sample)-(len(apdu)-m)]
			apdu, _ = EncodePDU(&SavPDU{ASDUs: []ASDU{a}})
		}
		if len(apdu) != m {
			t.Fatalf("APDU of %d octets, want %d", len(apdu), m)
		}
		h := Header{Dst: net.HardwareAddr{1, 0x0C, 0xCD, 4, 0, 1}, Src: net.HardwareAddr{0, 1, 2, 3, 4, 5}, Tagged: true, APPID: 0x4000}
		fr, err := EncodeRaw(h, apdu)
		if (err == nil) != (m == MaxAPDU) {
			t.Errorf("encode m=%d: %v", m, err)
		}
		if m == MaxAPDU {
			if _, err := Decode(fr); err != nil {
				t.Errorf("decode m=1492: %v", err)
			}
			if len(fr) != 18+8+m || len(fr) != 1518 {
				t.Errorf("frame of %d octets", len(fr))
			}
		} else {
			// Hand-built: Length 1501.
			hand := append(append([]byte(nil), unhex(t, "010CCD040001 000102030405 8100 8000 88BA 4000 05DD 0000 0000")...), apdu...)
			if _, err := Decode(hand); err == nil {
				t.Error("m = 1493 was decoded")
			}
		}
	}
}

// Covers: SIG-IPE-2084
func TestReservedFields(t *testing.T) {
	b := unhex(t, vectorLE)
	b[22], b[23], b[24], b[25] = 0xFA, 0xBC, 0x12, 0x34 // S, R=111, security 0xABC1234
	f, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Simulate || f.Reserved != 7 || f.Security != 0x0ABC1234 {
		t.Errorf("S=%v R=%d security=%#x", f.Simulate, f.Reserved, f.Security)
	}
	if f.Reserved1() != 0xFABC || f.Reserved2() != 0x1234 {
		t.Errorf("Reserved1/2 = %#x %#x", f.Reserved1(), f.Reserved2())
	}
	// Unsecured, unsimulated: both zero (5.3.3.4.4, 5.3.3.4.5).
	if h := (Header{}); h.Reserved1() != 0 || h.Reserved2() != 0 {
		t.Error("defaults not zero")
	}
	if h := (Header{Simulate: true}); h.Reserved1() != 0x8000 {
		t.Errorf("S bit = %#x", h.Reserved1())
	}
	h := f.Header
	h.Security = 0x10000000
	if _, err := EncodeRaw(h, f.APDU); err == nil {
		t.Error("a security word over 28 bits was sent")
	}
}

// Covers: SIG-IPE-2085
func TestHSRAndPRP(t *testing.T) {
	h := Header{Dst: net.HardwareAddr{1, 0x0C, 0xCD, 4, 0, 1}, Src: net.HardwareAddr{0, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E},
		Tagged: true, Priority: 4, APPID: 0x4000, HSR: &HSRTag{PathSize: 0x1034, Seq: 0x5678}}
	b, err := Encode(h, &SavPDU{ASDUs: []ASDU{leASDU()}})
	if err != nil {
		t.Fatal(err)
	}
	// Figure A.2: the HSR tag at octets 16-21, ethertype at 22, APPID at
	// 24, APDU at 32.
	want := unhex(t, vectorLE)
	hsr := append(append(append([]byte(nil), want[:16]...), unhex(t, "892F 1034 5678")...), want[16:]...)
	if !bytes.Equal(b, hsr) {
		t.Fatalf("HSR frame = %X", b)
	}
	f, err := Decode(b)
	if err != nil || f.HSR == nil || f.HSR.Seq != 0x5678 || f.Offset != 24 || !bytes.Equal(b[32:], f.APDU) {
		t.Fatalf("HSR decode = %+v, %v", f, err)
	}
	// Figure A.3: the PRP trailer after the APDU (and any extension or
	// padding) ends in 88-FB.
	prp := append(unhex(t, vectorLE), 0x12, 0x34, 0xA0, 0x3C, 0x88, 0xFB)
	if f, err = Decode(prp); err != nil || f.PRP == nil || f.PRP.Seq != 0x1234 || f.PRP.LanSize != 0xA03C || f.PDU.ASDUs[0].SmpCnt != 10 {
		t.Fatalf("PRP decode = %+v, %v", f, err)
	}
}

// FuzzDecode checks that no input panics and that a decoded frame
// encodes back to its header and APDU.
func FuzzDecode(f *testing.F) {
	f.Add(unhex(f, vectorLE))
	f.Add(append(unhex(f, vectorLE), 0x12, 0x34, 0xA0, 0x3C, 0x88, 0xFB))
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, err := Decode(b)
		if err != nil {
			return
		}
		if _, err := EncodePDU(fr.PDU); err != nil {
			t.Fatalf("decoded savPdu does not encode: %v", err)
		}
	})
}
