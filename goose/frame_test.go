package goose

import (
	"encoding/hex"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var (
	gooseDst = net.HardwareAddr{0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01}
	svDst    = net.HardwareAddr{0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01}
	src      = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
)

// Covers: SIG-IPE-360
func TestGOOSEDecodeByteVector(t *testing.T) {
	// A hand-assembled frame: 802.1Q priority 4, APPID 1, and a goosePdu
	// with a boolean and a quality in allData.
	b := unhex(t, `
		01 0c cd 01 00 01  00 11 22 33 44 55  81 00 80 00  88 b8
		00 01 00 3d 00 00 00 00
		61 33
		  80 01 47  81 02 07 d0  82 01 44  83 01 49
		  84 08 65 53 f1 00 00 00 00 0a
		  85 01 05  86 01 00  87 01 00  88 01 01  89 01 00  8a 01 02
		  ab 08 83 01 01 84 03 03 00 00`)
	f, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	g := f.GOOSE
	if f.APPID != 1 || f.VLAN != 0 || f.Priority != 4 || f.Dst.String() != gooseDst.String() || f.Src.String() != src.String() || f.Simulated {
		t.Errorf("header = %+v", f)
	}
	if g.GoCBRef != "G" || g.TAL != 2*time.Second || g.DatSet != "D" || g.GoID != "I" || g.StNum != 5 || g.SqNum != 0 ||
		g.ConfRev != 1 || g.NdsCom || g.Simulation || g.NumEntries != 2 || !g.T.Equal(time.Unix(1_700_000_000, 0)) {
		t.Errorf("goosePdu = %+v", g)
	}
	if len(g.AllData) != 2 || g.AllData[0].Kind != mms.KBool || !g.AllData[0].Bool || g.AllData[1].Kind != mms.KBitString || g.AllData[1].Bits.NBits != 13 {
		t.Errorf("allData = %+v", g.AllData)
	}
	q := dataJSON("x.q", g.AllData[1]).(map[string]any)
	if q["validity"] != "good" {
		t.Errorf("quality = %v", q)
	}

	// Our encoder produces the same PDU.
	enc := EncodeGOOSE(Frame{Dst: gooseDst, Src: src, VLAN: 0, Priority: 4, APPID: 1, GOOSE: &GOOSE{
		GoCBRef: "G", TAL: 2 * time.Second, DatSet: "D", GoID: "I", T: time.Unix(1_700_000_000, 0), StNum: 5, ConfRev: 1,
		AllData: []mms.Data{mms.Boolean(true), mms.Bits(mms.NewBitString(13))}}})
	if len(enc) != len(b) || hex.EncodeToString(enc[:30]) != hex.EncodeToString(b[:30]) {
		t.Errorf("encoded\n%x\nwant\n%x", enc, b)
	}
	if _, err := Decode(enc); err != nil {
		t.Errorf("decoding our own frame: %v", err)
	}

	// Malformed frames are refused with a reason.
	for name, bad := range map[string][]byte{
		"short":         b[:10],
		"length":        append(append([]byte(nil), b[:20]...), 0xff, 0xff, 0, 0, 0, 0),
		"pdu tag":       append(append([]byte(nil), b[:26]...), append([]byte{0x62}, b[27:]...)...),
		"truncated pdu": b[:len(b)-3],
	} {
		if _, err := Decode(bad); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	entries := append([]byte(nil), b...)
	entries[strings.Index(hex.EncodeToString(b), "8a0102")/2+2] = 3
	if _, err := Decode(entries); err == nil || !strings.Contains(err.Error(), "announces 3") {
		t.Errorf("entry count mismatch = %v", err)
	}
	other := append([]byte(nil), b...)
	other[12], other[13] = 0x08, 0x00
	if _, err := Decode(other); err != ErrNotGOOSEorSV {
		t.Errorf("IPv4 frame = %v", err)
	}
}

// Covers: SIG-IPE-361
func TestSVDecode(t *testing.T) {
	samples := make([]Sample, 8)
	for i := range samples {
		samples[i] = Sample{Value: int32(i*1000 - 3000), Quality: uint32(i % 2)}
	}
	f := Frame{Dst: svDst, Src: src, VLAN: -1, APPID: 0x4000, SV: &SV{ASDUs: []ASDU{
		{SvID: "MU01", SmpCnt: 3999, ConfRev: 1, SmpSynch: 2, SeqData: SeqData(samples)},
		{SvID: "MU01", DatSet: "MU/LLN0$PhsMeas1", SmpCnt: 0, ConfRev: 1, SmpSynch: 2, SmpRate: 80, SeqData: SeqData(samples),
			RefrTm: time.Unix(1_700_000_000, 500_000_000)},
	}}}
	b := EncodeSV(f)
	// The smpCnt field keeps its two octets even when small.
	if !strings.Contains(hex.EncodeToString(b), "82020f9f") || !strings.Contains(hex.EncodeToString(b), "82020000") {
		t.Errorf("smpCnt encoding in %x", b)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.EtherType != EtherTypeSV || got.APPID != 0x4000 || got.VLAN != -1 || len(got.SV.ASDUs) != 2 {
		t.Fatalf("frame = %+v", got)
	}
	a := got.SV.ASDUs[1]
	if a.SvID != "MU01" || a.DatSet != "MU/LLN0$PhsMeas1" || a.SmpCnt != 0 || a.ConfRev != 1 || a.SmpSynch != 2 || a.SmpRate != 80 ||
		math.Abs(float64(a.RefrTm.Sub(time.Unix(1_700_000_000, 500_000_000)))) > float64(time.Microsecond) {
		t.Errorf("ASDU = %+v", a)
	}
	if got.SV.ASDUs[0].SmpCnt != 3999 {
		t.Errorf("smpCnt = %d", got.SV.ASDUs[0].SmpCnt)
	}
	s, err := a.Samples()
	if err != nil || len(s) != 8 || s[0].Value != -3000 || s[7].Value != 4000 || s[1].Quality != 1 {
		t.Errorf("samples = %v %v", s, err)
	}
	if q := SampleQuality(2 | 1<<11); q != "invalid,test" {
		t.Errorf("quality = %q", q)
	}
	// A sequence of data that is not value/quality pairs is refused.
	if _, err := (ASDU{SeqData: make([]byte, 12)}).Samples(); err == nil {
		t.Error("12 octets split into samples")
	}
	// A wrong ASDU count is refused.
	bad := append([]byte(nil), b...)
	i := strings.Index(hex.EncodeToString(bad), "800102") / 2
	bad[i+2] = 3
	if _, err := Decode(bad); err == nil {
		t.Error("an SV frame announcing 3 ASDUs with 2 decoded")
	}
}

// Covers: SIG-IPE-364
func TestSVAggregates(t *testing.T) {
	// 50 Hz at 4000 samples per second: 230 V RMS on Va, 100 A on Ia.
	const rate = 4000
	agg := NewAggregator([]int{0, 4}, []float64{0.001, 0.01}, rate, rate, 1)
	var res Result
	done := false
	for n := 0; n < rate; n++ {
		ph := 2 * math.Pi * 50.02 * float64(n) / rate
		s := make([]Sample, 8)
		s[0].Value = int32(math.Round(100 * math.Sqrt2 * math.Sin(ph) / 0.001))
		s[4].Value = int32(math.Round(230 * math.Sqrt2 * math.Sin(ph+0.3) / 0.01))
		if n == 17 {
			s[0].Quality = 3 // questionable
		}
		res, done = agg.Add(s, 1)
	}
	if !done {
		t.Fatal("no result after a full window")
	}
	if math.Abs(res.RMS[0]-100) > 0.05 || math.Abs(res.RMS[1]-230) > 0.05 {
		t.Errorf("RMS = %v", res.RMS)
	}
	if math.Abs(res.Frequency-50.02) > 0.005 {
		t.Errorf("frequency = %v", res.Frequency)
	}
	if res.Quality[0] != "questionable" || res.Quality[1] != "good" {
		t.Errorf("quality = %v", res.Quality)
	}
	// Missing samples (a step of 2) keep the frequency right.
	agg = NewAggregator([]int{0}, []float64{1}, 1000, rate, 0)
	for n := 0; n < 2000; n += 2 {
		v := int32(1000 * math.Sin(2*math.Pi*49.9*float64(n)/rate))
		res, done = agg.Add([]Sample{{Value: v}}, 2)
	}
	if !done || math.Abs(res.Frequency-49.9) > 0.01 {
		t.Errorf("frequency with gaps = %v (%v)", res.Frequency, done)
	}
}
