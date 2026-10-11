package goose

import (
	"bytes"
	"encoding/hex"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

// These tests follow IEC 61850-8-1 Ed. 2.1 (2011+AMD1:2020): the frame of
// Annex C, the grammar of Annex A, the fixed-length encoding of A.3 and
// the publisher/subscriber state machines of 18.1.2.5. The byte vectors
// are assembled field by field from those clauses.

// A frame per 8-1 Figure C.1: 802.1Q tag (Figure C.4: priority 4, CFI 0,
// VID 5), ethertype 88-B8, APPID 0x3001, length 8+m, Reserved 1 with
// the S bit, a reserved bit and a security value set (Figure C.5),
// Reserved 2 = 0x1234, then the goosePdu and pad octets up to the
// Ethernet minimum.
const c1Frame = `
	01 0c cd 01 00 22  00 11 22 33 44 55  81 00 80 05  88 b8
	30 01 00 31 f0 07 12 34
	61 27
	  80 01 47  81 01 64  82 01 44  83 01 49
	  84 08 65 53 f1 00 80 00 00 2a
	  85 01 02  86 01 03  88 01 01  8a 01 01
	  ab 03 83 01 00
	00 00 00 00 00 00 00 00 00 00`

// Covers: SIG-IPE-1850
func TestGOOSEFrameAnnexC(t *testing.T) {
	b := unhex(t, c1Frame)
	f, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if f.Priority != 4 || f.VLAN != 5 || f.EtherType != EtherTypeGOOSE || f.APPID != 0x3001 {
		t.Errorf("header = prio %d vid %d et %#x appid %#x", f.Priority, f.VLAN, f.EtherType, f.APPID)
	}
	// S is the first bit of Reserved 1; the rest and Reserved 2 are
	// ignored by the subscriber (C.2.5) and only kept.
	if !f.Simulated || f.Reserved1 != 0x7007 || f.Reserved2 != 0x1234 {
		t.Errorf("reserved = S %v r1 %#x r2 %#x", f.Simulated, f.Reserved1, f.Reserved2)
	}
	g := f.GOOSE
	if g.TAL != 100*time.Millisecond || g.StNum != 2 || g.SqNum != 3 || g.Simulation || g.NdsCom || len(g.AllData) != 1 {
		t.Errorf("pdu = %+v", g)
	}
	// t: seconds, 24-bit fraction (0x800000 = half a second) and the
	// time quality octet (Table 36): 0x2a = not synchronised, 10 bits.
	if !g.T.Equal(time.Unix(1_700_000_000, 500_000_000)) || g.TQuality != 0x2a {
		t.Errorf("t = %v quality %#x", g.T, g.TQuality)
	}
	// An untagged frame (the tag removed on the way, C.2.4) decodes too.
	untagged := append(append([]byte(nil), b[:12]...), b[16:]...)
	if u, err := Decode(untagged); err != nil || u.VLAN != -1 || u.GOOSE.StNum != 2 {
		t.Errorf("untagged = %+v, %v", u, err)
	}
	// Length is 8 + m with m below 1492; frames with an inconsistent or
	// invalid length are discarded.
	for name, l := range map[string]uint16{"below 8": 7, "beyond the frame": 0x60, "m of 1492": 1500} {
		bad := append([]byte(nil), b...)
		bad[20], bad[21] = byte(l>>8), byte(l)
		if _, err := Decode(bad); err == nil {
			t.Errorf("length %s decoded", name)
		}
	}
	// GSE management (88-B9) is another ethertype: not decoded as GOOSE.
	mng := append([]byte(nil), b...)
	mng[16], mng[17] = 0x88, 0xb9
	if _, err := Decode(mng); err != ErrNotGOOSEorSV {
		t.Errorf("management frame = %v", err)
	}
}

// Covers: SIG-IPE-1851
func TestGOOSEPduAnnexA(t *testing.T) {
	// Our encoder: every field in grammar order with its context tag,
	// goID always present (not OPTIONAL in A.1), BER minimal integers
	// with a leading zero octet where the top bit is set (128 = 00 80).
	enc := EncodeGOOSE(Frame{Dst: gooseDst, Src: src, VLAN: 0, Priority: 4, APPID: 1, GOOSE: &GOOSE{
		GoCBRef: "G", TAL: 128 * time.Millisecond, DatSet: "D", T: time.Unix(1_700_000_000, 0), TQuality: 0x0a,
		StNum: 255, SqNum: 0, ConfRev: 1, NdsCom: true, AllData: []mms.Data{mms.Boolean(true)}}})
	want := unhex(t, `
		01 0c cd 01 00 01  00 11 22 33 44 55  81 00 80 00  88 b8
		00 01 00 38 00 00 00 00
		61 2e
		  80 01 47  81 02 00 80  82 01 44  83 00
		  84 08 65 53 f1 00 00 00 00 0a
		  85 02 00 ff  86 01 00  87 01 00  88 01 01  89 01 ff  8a 01 01
		  ab 03 83 01 ff`)
	if !bytes.Equal(enc, want) {
		t.Errorf("encoded\n%x\nwant\n%x", enc, want)
	}
	// simulation and ndsCom are DEFAULT FALSE: absent reads as false.
	b := unhex(t, c1Frame)
	if f, _ := Decode(b); f.GOOSE.Simulation || f.GOOSE.NdsCom || f.GOOSE.GoID != "I" {
		t.Errorf("defaults = %+v", f.GOOSE)
	}
	// Every other field is mandatory: dropping one (gocbRef, 3 octets at
	// offset 28) is refused.
	short := append(append([]byte(nil), b[:28]...), b[31:]...)
	short[27] -= 3
	short[21] -= 3
	if _, err := Decode(short); err == nil || !strings.Contains(err.Error(), "mandatory field 0") {
		t.Errorf("without gocbRef = %v", err)
	}
}

// The fixed-length encoding of 8-1 A.3 (Tables A.1 to A.3): header
// integers in 5 octets, allData members at their fixed sizes, visible
// strings NUL-padded to 35 octets. The integer values are the fixed-size
// column of Table A.3.
//
// Covers: SIG-IPE-1852
func TestGOOSEFixedLengthAnnexA3(t *testing.T) {
	vis := "61 62 63" + strings.Repeat(" 00", 32)
	pdu := `
		80 01 47  81 05 00 00 00 07 d0  82 01 44  83 01 49
		84 08 65 53 f1 00 00 00 00 0a
		85 05 00 00 00 00 05  86 05 00 00 00 00 01  87 01 00  88 05 00 00 00 00 01
		89 01 00  8a 05 00 00 00 00 0d
		ab 6d
		  83 01 01
		  85 02 ff ff
		  85 03 ff ff 7f
		  85 05 ff ff ff 80 00
		  85 09 ff ff ff ff ff ff ff 7f ff
		  86 02 00 ff
		  86 03 00 ff ff
		  86 05 00 ff ff ff ff
		  87 05 08 43 66 00 00
		  84 02 06 80
		  84 03 03 00 00
		  8a 23 ` + vis + `
		  91 08 65 53 f1 00 00 00 00 0a`
	body := unhex(t, pdu)
	apdu := append([]byte{0x61, 0x81, byte(len(body))}, body...)
	hdr := unhex(t, "01 0c cd 01 00 01  00 11 22 33 44 55  88 b8  00 01")
	frame := append(hdr, byte((8+len(apdu))>>8), byte(8+len(apdu)), 0, 0, 0, 0)
	frame = append(frame, apdu...)
	f, err := Decode(frame)
	if err != nil {
		t.Fatal(err)
	}
	g := f.GOOSE
	if g.TAL != 2*time.Second || g.StNum != 5 || g.SqNum != 1 || g.ConfRev != 1 || g.NumEntries != 13 {
		t.Errorf("header = %+v", g)
	}
	d := g.AllData
	ints := []int64{-1, -129, -32768, -32769}
	for i, w := range ints {
		if d[1+i].Kind != mms.KInt || d[1+i].Int != w {
			t.Errorf("signed member %d = %+v, want %d", i, d[1+i], w)
		}
	}
	for i, w := range []uint64{255, 65535, math.MaxUint32} {
		if d[5+i].Kind != mms.KUint || d[5+i].Uint != w {
			t.Errorf("unsigned member %d = %+v, want %d", i, d[5+i], w)
		}
	}
	if !d[0].Bool || d[8].Float != 230 || dataJSON("pos", d[9]) != "on" || d[11].Str != "abc" {
		t.Errorf("members = %+v", d)
	}
	if q := dataJSON("x.q", d[10]).(map[string]any); q["validity"] != "good" {
		t.Errorf("quality = %v", q)
	}
	if !d[12].Time.T.Equal(time.Unix(1_700_000_000, 0)) {
		t.Errorf("timestamp = %v", d[12].Time)
	}
	// The BER column of Table A.3 gives the same values.
	for enc, w := range map[string]int64{"85 01 ff": -1, "85 02 ff 7f": -129, "85 02 80 00": -32768, "85 03 ff 7f ff": -32769, "85 02 7f ff": 32767} {
		e, _, err := mms.Parse(unhex(t, enc))
		if err != nil {
			t.Fatal(err)
		}
		if v, err := decodeGOOSEData(e); err != nil || v.Int != w {
			t.Errorf("%s = %v %v, want %d", enc, v.Int, err, w)
		}
	}
}

// 8-1 Figures C.2 and C.3: an HSR tag between the 802.1Q tag and the
// ethertype, and a PRP trailer after the APDU.
//
// Covers: SIG-IPE-1853
func TestGOOSEHSRAndPRP(t *testing.T) {
	b := unhex(t, c1Frame)
	hsr := append(append(append([]byte(nil), b[:16]...), 0x89, 0x2f, 0x00, 0x40, 0x12, 0x34), b[16:]...)
	f, err := Decode(hsr)
	if err != nil || !f.HSR || f.VLAN != 5 || f.GOOSE.StNum != 2 {
		t.Fatalf("HSR tagged = %+v, %v", f, err)
	}
	untagged := append(append([]byte(nil), hsr[:12]...), hsr[16:]...)
	if f, err := Decode(untagged); err != nil || !f.HSR || f.VLAN != -1 {
		t.Errorf("untagged HSR = %+v, %v", f, err)
	}
	// The PRP trailer: sequence number, LAN and size, suffix 88-FB.
	prp := append(append([]byte(nil), b[:len(b)-10]...), 0x12, 0x34, 0xa0, 0x3c, 0x88, 0xfb)
	if f, err := Decode(prp); err != nil || f.GOOSE.SqNum != 3 {
		t.Errorf("PRP trailer = %+v, %v", f, err)
	}
	if _, err := Decode(hsr[:19]); err == nil {
		t.Error("a truncated HSR tag decoded")
	}
}

// Covers: SIG-IPE-1854
func TestGOOSEArrivalClassification(t *testing.T) {
	const max = math.MaxUint32
	for _, c := range []struct {
		seen             bool
		st, sq, nst, nsq uint32
		want             Arrival
		gap              bool
	}{
		{false, 0, 0, 7, 3, ArrivalFirst, false},
		{true, 5, 3, 5, 4, ArrivalRetransmission, false},
		{true, 5, 3, 5, 6, ArrivalRetransmission, true}, // sqNum 4 and 5 lost
		{true, 5, 3, 5, 3, ArrivalDuplicate, false},
		{true, 5, 3, 5, 2, ArrivalOld, false},
		{true, 5, 3, 6, 0, ArrivalNewState, false},
		{true, 5, 3, 8, 0, ArrivalNewState, true}, // stNum 6 and 7 lost
		{true, 5, 3, 4, 9, ArrivalOld, false},     // an earlier state, late
		{true, 5, 3, 1, 0, ArrivalRestart, false}, // stNum back to its initial 1
		{true, 5, 3, 1, 1, ArrivalRestart, false},
		{true, 5, 3, 1, 5, ArrivalOld, false}, // stNum 1, late
		{true, 5, 30, 5, 0, ArrivalRestart, false},
		{true, 5, max, 5, 1, ArrivalRetransmission, false}, // sqNum skips 0 on wrap
		{true, max, 9, 1, 0, ArrivalNewState, false},       // stNum skips 0 on wrap
		{true, max, 9, 2, 0, ArrivalNewState, true},
	} {
		got, gap := Classify(c.seen, c.st, c.sq, c.nst, c.nsq)
		if got != c.want || gap != c.gap {
			t.Errorf("(%d,%d) then (%d,%d) = %v gap %v, want %v gap %v", c.st, c.sq, c.nst, c.nsq, got, gap, c.want, c.gap)
		}
	}
}

func testPublication(t *testing.T) *Publication {
	t.Helper()
	p := &Publication{ID: "p", GoCBRef: "SIGMA1LD0/LLN0$GO$gcb1", DataSet: "SIGMA1LD0/LLN0$DS1", APPID: 0x3001 + 1,
		DstMAC: "01:0c:cd:01:00:10", SrcMAC: "02:00:00:00:00:01", ConfRev: 3,
		MinTime: (4 * time.Millisecond), MaxTime: (100 * time.Millisecond),
		Members: []PubMember{{"trip", "boolean"}, {"pos", "dbpos"}, {"q", "quality"}}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

// 8-1 Figure 10 and Figure 8; 7-2 Table 94.
//
// Covers: SIG-IPE-1857
func TestGOOSEPublisherStateMachine(t *testing.T) {
	p := NewPublisher(testPublication(t))
	now := time.Unix(1_700_000_000, 0)
	dec := func(b []byte) *GOOSE {
		t.Helper()
		f, err := Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		return f.GOOSE
	}
	if _, ok := p.Due(now); ok {
		t.Error("a disabled publisher sent")
	}
	// Enabling sends at once: stNum 1, sqNum 0, t = now; the next message
	// follows after MinTime and timeAllowedtoLive covers twice that.
	g := dec(p.Enable(now))
	if g.StNum != 1 || g.SqNum != 0 || !g.T.Equal(now) || g.TAL != 8*time.Millisecond {
		t.Errorf("first = %+v", g)
	}
	if _, ok := p.Due(now.Add(3 * time.Millisecond)); ok {
		t.Error("repeated before MinTime")
	}
	// Repetitions: 4, 8, 16, 32, 64, then 100 (MaxTime) ms apart; sqNum
	// counts up, t stays the time of the last change.
	at := now
	var gaps []time.Duration
	for i := 1; i <= 8; i++ {
		next := p.NextAt()
		gaps = append(gaps, next.Sub(at))
		at = next
		b, ok := p.Due(at)
		if !ok {
			t.Fatalf("repetition %d not due", i)
		}
		g = dec(b)
		if g.SqNum != uint32(i) || g.StNum != 1 || !g.T.Equal(now) || g.TAL < p.NextAt().Sub(at) {
			t.Errorf("repetition %d = %+v", i, g)
		}
	}
	if want := []time.Duration{4, 8, 16, 32, 64, 100, 100, 100}; len(gaps) == len(want) {
		for i := range want {
			if gaps[i] != want[i]*time.Millisecond {
				t.Errorf("interval %d = %v, want %v ms", i, gaps[i], want[i])
			}
		}
	}
	// A change: stNum 2, sqNum 0, new t (to the 2^-24 s of UtcTime), back
	// to MinTime.
	later := at.Add(time.Millisecond)
	b, changed, err := p.Set(map[string]any{"trip": true, "pos": "on"}, later)
	if err != nil || !changed || b == nil {
		t.Fatalf("set = %v %v", changed, err)
	}
	g = dec(b)
	if g.StNum != 2 || g.SqNum != 0 || g.T.Sub(later).Abs() > time.Microsecond || !g.AllData[0].Bool || dataJSON("pos", g.AllData[1]) != "on" || g.TAL != 8*time.Millisecond {
		t.Errorf("after the change = %+v", g)
	}
	// The same values again are no change.
	if b, changed, err := p.Set(map[string]any{"trip": true}, later); b != nil || changed || err != nil {
		t.Errorf("unchanged set = %v %v %v", b != nil, changed, err)
	}
	// Refused values change nothing.
	for _, bad := range []map[string]any{{"nope": 1.0}, {"trip": "yes"}, {"pos": "open"}, {"q": map[string]any{"validity": "fine"}}} {
		if _, _, err := p.Set(bad, later); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if st, _ := p.State(); st != 2 {
		t.Errorf("stNum after refusals = %d", st)
	}
	// Both counters skip 0 when they wrap.
	p.sqNum = math.MaxUint32
	if b, ok := p.Due(p.NextAt()); !ok || dec(b).SqNum != 1 {
		t.Error("sqNum did not wrap to 1")
	}
	p.stNum = math.MaxUint32
	if b, _, _ := p.Set(map[string]any{"trip": false}, later); b == nil || dec(b).StNum != 1 || dec(b).SqNum != 0 {
		t.Error("stNum did not wrap to 1")
	}
	p.Disable()
	if _, ok := p.Due(later.Add(time.Hour)); ok || !p.NextAt().IsZero() {
		t.Error("sent after GoEna false")
	}
}

// 8-1 C.2.2 to C.2.5 and B; 7-2 Table 87.
//
// Covers: SIG-IPE-1858
func TestGOOSEPublisherFrameAndSettings(t *testing.T) {
	pc := testPublication(t)
	pc.Simulation = true
	b := NewPublisher(pc).Enable(time.Unix(1_700_000_000, 0))
	// Always 802.1Q tagged, default VID 0 and priority 4, CFI 0.
	if hex.EncodeToString(b[12:20]) != "810080"+"0088b83001" {
		t.Errorf("tag, ethertype and APPID = %x", b[12:21])
	}
	f, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	// The S bit mirrors the PDU's simulation; goID defaults to the
	// control block reference; the time accuracy is "unspecified".
	g := f.GOOSE
	if !f.Simulated || !g.Simulation || g.GoID != pc.GoCBRef || g.ConfRev != 3 || g.TQuality != 0x1f || g.NumEntries != 3 || len(b)-26 != int(b[21])-8 {
		t.Errorf("frame = %+v %+v", f, g)
	}
	ok := func(mod func(p *Publication)) error {
		p := Publication{ID: "p", GoCBRef: "L/LLN0$GO$g", DataSet: "L/LLN0$D", APPID: 2, DstMAC: "01:0c:cd:01:00:01", ConfRev: 1,
			Members: []PubMember{{"a", "boolean"}}}
		mod(&p)
		return p.Validate()
	}
	for name, mod := range map[string]func(p *Publication){
		"APPID 0x0001": func(p *Publication) { p.APPID = 0x0001 + 1 },
		"APPID 0x3FFF": func(p *Publication) { p.APPID = 0x3fff + 1 },
		"APPID 0x8000": func(p *Publication) { p.APPID = 0x8000 + 1 },
		"APPID 0xBFFF": func(p *Publication) { p.APPID = 0xbfff + 1 },
		"VID 4095":     func(p *Publication) { v := 4095; p.VLANID = &v },
		"MaxTime 60s":  func(p *Publication) { p.MaxTime = (time.Minute) },
	} {
		if err := ok(mod); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	for name, mod := range map[string]func(p *Publication){
		"APPID 0x0000":    func(p *Publication) { p.APPID = 0 + 1 },
		"APPID 0x4000":    func(p *Publication) { p.APPID = 0x4000 + 1 },
		"APPID 0xC000":    func(p *Publication) { p.APPID = 0xc000 + 1 },
		"no APPID":        func(p *Publication) { p.APPID = 0 },
		"unicast dst":     func(p *Publication) { p.DstMAC = "00:0c:cd:01:00:01" },
		"multicast src":   func(p *Publication) { p.SrcMAC = "01:00:00:00:00:01" },
		"confRev 0":       func(p *Publication) { p.ConfRev = 0 },
		"priority 8":      func(p *Publication) { v := 8; p.Priority = &v },
		"MaxTime 61s":     func(p *Publication) { p.MaxTime = (61 * time.Second) },
		"MinTime > Max":   func(p *Publication) { p.MinTime, p.MaxTime = (time.Second), (time.Millisecond) },
		"gocbRef 130":     func(p *Publication) { p.GoCBRef = strings.Repeat("x", 130) },
		"no members":      func(p *Publication) { p.Members = nil },
		"unknown type":    func(p *Publication) { p.Members = []PubMember{{"a", "int128"}} },
		"duplicate names": func(p *Publication) { p.Members = []PubMember{{"a", "boolean"}, {"a", "int8"}} },
	} {
		if err := ok(mod); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Member types encode with the MMS Data tags of 8-1 Table A.2.
//
// Covers: SIG-IPE-1859
func TestGOOSEPublishedMemberTypes(t *testing.T) {
	for _, c := range []struct {
		typ string
		v   any
		enc string
	}{
		{"boolean", true, "8301ff"},
		{"int8", -1.0, "8501ff"},
		{"enum", 3.0, "850103"},
		{"int16", -129.0, "8502ff7f"},
		{"int32", 2147483647.0, "85047fffffff"},
		{"int64", -32769.0, "8503ff7fff"},
		{"int8u", 255.0, "860200ff"},
		{"int16u", 65535.0, "860300ffff"},
		{"int32u", 4294967295.0, "860500ffffffff"},
		{"float32", 230.0, "87050843660000"},
		{"dbpos", "off", "84020640"},
		{"dbpos", "bad", "840206c0"},
		{"quality", "invalid", "8403034000"},
		{"quality", map[string]any{"validity": "questionable", "test": true}, "840303c010"},
		{"visstring", "abc", "8a03616263"},
		{"octets", "0a0b", "89020a0b"},
		{"timestamp", "2023-11-14T22:13:20Z", "91086553f1000000001f"},
	} {
		d, err := memberValue(c.typ, c.v)
		if err != nil {
			t.Errorf("%s %v: %v", c.typ, c.v, err)
			continue
		}
		if got := hex.EncodeToString(d.Encode()); got != c.enc {
			t.Errorf("%s %v = %s, want %s", c.typ, c.v, got, c.enc)
		}
	}
	for _, c := range []struct {
		typ string
		v   any
	}{{"int8", 128.0}, {"int8u", -1.0}, {"int16", 1.5}, {"int32u", 4294967296.0}, {"boolean", 1.0}, {"octets", "xyz"}, {"timestamp", "yesterday"}, {"quality", 3.0}} {
		if _, err := memberValue(c.typ, c.v); err == nil {
			t.Errorf("%s %v accepted", c.typ, c.v)
		}
	}
}
