package goose

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850/goose/sv"
)

// The goose IPE decodes SV with the IEC 61850-9-2 Ed. 2.1 codec: quality
// by Table 21 (0x0842 is invalid, failure, test), gmIdentity and smpMod
// read, fixed sizes enforced, an APDU of 1492 octets taken.
//
// Covers: SIG-IPE-2104
func TestSVDecodedWithSVCodec(t *testing.T) {
	gm := [8]byte{0, 0x1B, 0x19, 0xFF, 0xFE, 0, 0, 1}
	mod := sv.SmpPerSecond
	b, err := sv.Encode(sv.Header{Dst: net1, Src: net2, Tagged: true, Priority: 4, APPID: 0x4000},
		&sv.SavPDU{ASDUs: []sv.ASDU{{SvID: "MU01", SmpCnt: 7, ConfRev: 1, SmpSynch: 2, SmpMod: &mod, GmIdentity: &gm,
			Sample: []byte{0, 0, 3, 0xE8, 0, 0, 8, 0x42}}}})
	if err != nil {
		t.Fatal(err)
	}
	f, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	a := f.SV.ASDUs[0]
	if a.SmpCnt != 7 || !a.SmpModSet || a.SmpMod != 1 || a.GmIdentity == nil || *a.GmIdentity != gm {
		t.Errorf("ASDU = %+v", a)
	}
	s, _ := a.Samples()
	if q := SampleQuality(s[0].Quality); q != "invalid,failure,test" {
		t.Errorf("quality 0x0842 = %q", q)
	}
	// Table 14: smpCnt in one octet is refused (the 9-2 LE decoder took it).
	i := bytes.Index(b, []byte{0x82, 0x02, 0x00, 0x07})
	short := append(append(append([]byte(nil), b[:i]...), 0x82, 0x01, 0x07), b[i+4:]...)
	short[21]-- // Length
	short[27]-- // savPdu
	short[32]-- // asdu
	short[34]-- // ASDU
	if _, err := Decode(short); err == nil {
		t.Error("a one-octet smpCnt was decoded")
	}
	// An APDU of 1492 octets (m < 1493, 9-2 5.3.3.4.3) is taken for SV.
	big := EncodeSV(Frame{Dst: net1, Src: net2, VLAN: 0, Priority: 4, APPID: 0x4000, SV: &SV{ASDUs: []ASDU{{SvID: "MU01", ConfRev: 1, SeqData: make([]byte, 1492-38)}}}})
	if m := len(big) - 26; m != 1492 {
		t.Fatalf("APDU of %d octets", m)
	}
	if _, err := Decode(big); err != nil {
		t.Errorf("m = 1492: %v", err)
	}
}

// F-1081: the Layer 2 extension goes into the same 1500-octet payload as
// the APDU, so SecureL2 refuses a frame whose 8 + m + s exceeds it.
//
// Covers: SIG-IPE-2102
func TestSecureL2PayloadLimit(t *testing.T) {
	k, err := NewSecKey(KeySpec{KeyID: 3, MAC: "hmac-sha256-128", Key: hmacKey}, false)
	if err != nil {
		t.Fatal(err)
	}
	frame := func(m int) []byte {
		b := EncodeSV(Frame{Dst: net1, Src: net2, VLAN: 0, Priority: 4, APPID: 0x4000, SV: &SV{ASDUs: []ASDU{{SvID: "MU01", ConfRev: 1, SeqData: make([]byte, m-38)}}}})
		if len(b)-26 != m {
			t.Fatalf("APDU of %d octets, want %d", len(b)-26, m)
		}
		return b
	}
	if _, err := SecureL2(frame(1492), k, 0, -1, nil); err == nil || !strings.Contains(err.Error(), "more than Ethernet carries") {
		t.Errorf("m = 1492 secured: %v", err)
	}
	out, err := SecureL2(frame(1400), k, 0, -1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(out) - 18; n > 1500 {
		t.Errorf("secured payload of %d octets", n)
	}
}

// SVStream publishes through sv.Publisher: frames always tagged (VID 0,
// priority 4 when no VLAN is set), smpCnt free-running with the wrap of
// smpRate x nominal frequency, smpRate and datSet sent, a strictly
// increasing security timestamp.
//
// Covers: SIG-IPE-2103
func TestSVStreamOnPublisher(t *testing.T) {
	s := &SVStream{Dst: net1, Src: net2, VLAN: -1, APPID: 0x4000, SvID: "MU01", DataSet: "MU/LLN0$PhsMeas1", ConfRev: 1, SmpRate: 4, NominalHz: 50, SmpSynch: 2}
	now := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	var last time.Time
	for i := range 202 {
		b, err := s.Frame([]Sample{{Value: int32(i), Quality: 2}}, now.Add(time.Duration(i)*5*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		h, err := sv.Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		a := h.PDU.ASDUs[0]
		if !h.Tagged || h.VID != 0 || h.Priority != 4 || int(a.SmpCnt) != i%200 || *a.SmpRate != 4 || *a.DatSet != "MU/LLN0$PhsMeas1" || a.SmpSynch != 2 {
			t.Fatalf("frame %d: %+v %+v", i, h.Header, a)
		}
		f, _ := Decode(b)
		if !f.SV.SecurityT.After(last) {
			t.Fatalf("frame %d security timestamp not increasing", i)
		}
		last = f.SV.SecurityT
	}
	// The formerly reserved validity and smpSynch above 2 are not sent.
	if _, err := s.Frame([]Sample{{Quality: 1}}, now); err == nil {
		t.Error("validity 1 was sent")
	}
	bad := &SVStream{Dst: net1, Src: net2, VLAN: -1, APPID: 0x4000, SvID: "MU01", ConfRev: 1, SmpRate: 80, NominalHz: 50, SmpSynch: 5}
	if _, err := bad.Frame(make([]Sample, 8), now); err == nil {
		t.Error("smpSynch 5 was sent")
	}
	// A changed number of samples is refused (the data set is fixed).
	if _, err := s.Frame(make([]Sample, 2), now); err == nil {
		t.Error("another data set size was sent")
	}
}
