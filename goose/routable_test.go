package goose

import (
	"bytes"
	"errors"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

// An unsecured routable GOOSE SPDU assembled from 8-1 Annex J: RFC 1240
// LI 01 and UD 40 (6.3.2.2), SI A1, header length, PI 80 and its
// length, SPDU Length, SPDU Number 7, Version 2, TimeOfCurrentKey,
// TimeOfNextKey and KeyID all 0 (no HMAC or encryption), an empty IV,
// PayloadLength, then the GOOSE payload: tag 81, simulation, APPID,
// APDU length and the APDU.
const spduVector = `01 40  a1 17  80 15
	00 00 00 20  00 00 00 07  00 02  00 00 00 00  00 00  00 00 00 00  00
	00 00 00 0b
	81 00 30 01 00 05  61 03 80 01 47`

// Covers: SIG-IPE-1864
func TestRoutableSPDUAnnexJ(t *testing.T) {
	want := unhex(t, spduVector)
	apdu := unhex(t, "61 03 80 01 47")
	got, err := EncodeRoutable(SPDU{SI: SIGOOSE, Number: 7, Version: SessionVersion,
		Payloads: []Payload{{Tag: PayloadGOOSE, APPID: 0x3001, APDU: apdu}}})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("encoded %x, %v\nwant    %x", got, err, want)
	}
	s, err := DecodeRoutable(want)
	if err != nil || s.Number != 7 || len(s.Payloads) != 1 || s.Payloads[0].APPID != 0x3001 || !bytes.Equal(s.Payloads[0].APDU, apdu) {
		t.Fatalf("decoded %+v, %v", s, err)
	}
	// Two real goosePdus aggregated in one SPDU; padding and an HMAC
	// after the payload are ignored.
	g1 := goosePDU(t, 1, false)
	g2 := goosePDU(t, 2, true)
	b, err := EncodeRoutable(SPDU{SI: SIGOOSE, Version: SessionVersion, Payloads: []Payload{
		{Tag: PayloadGOOSE, APPID: 1, APDU: g1}, {Tag: PayloadGOOSE, APPID: 2, Simulation: true, APDU: g2}}})
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, 0xaf, 0x02, 0x02, 0x02, 1, 2, 3, 4, 5, 6, 7, 8)
	s, err = DecodeRoutable(b)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := s.Frames()
	if err != nil || len(fs) != 2 || !fs[0].Routable || fs[0].APPID != 1 || fs[0].GOOSE.StNum != 1 || fs[0].Dst != nil || fs[0].VLAN != -1 ||
		!fs[1].Simulated || fs[1].GOOSE.StNum != 2 {
		t.Fatalf("frames = %+v, %v", fs, err)
	}
	// Refusals.
	mod := func(i int, v byte) []byte {
		c := append([]byte(nil), want...)
		c[i] = v
		return c
	}
	for name, bad := range map[string][]byte{
		"RFC 1240 LI":       mod(0, 2),
		"UD code":           mod(1, 0x41),
		"SI 64":             mod(2, 0x40),
		"PI":                mod(4, 0x81),
		"version 1":         mod(15, 1),
		"SPDU length 64495": append(append(append([]byte(nil), want[:6]...), 0, 0, 0xfb, 0xef), want[10:]...),
		"IV beyond header":  mod(26, 1),
		"payload length":    mod(30, 0x0c),
		"SV under GOOSE SI": mod(31, PayloadSV),
		"APDU length":       mod(36, 6),
		"truncated":         want[:20],
	} {
		if _, err := DecodeRoutable(bad); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	// A KeyID other than 0 means IEC 62351-6 security: not supported.
	if _, err := DecodeRoutable(mod(25, 5)); !errors.Is(err, ErrSecuredSPDU) {
		t.Errorf("KeyID 5 = %v", err)
	}
	if _, err := EncodeRoutable(SPDU{SI: SIGOOSE, Payloads: []Payload{{Tag: PayloadSV}}}); err == nil {
		t.Error("an SV payload encoded under SI A1")
	}
}

func goosePDU(t *testing.T, st uint32, sim bool) []byte {
	t.Helper()
	eth := EncodeGOOSE(Frame{Dst: gooseDst, Src: src, VLAN: -1, APPID: 1, GOOSE: &GOOSE{GoCBRef: "G", TAL: time.Second, DatSet: "D",
		GoID: "I", T: time.Unix(1_700_000_000, 0), StNum: st, Simulation: sim, ConfRev: 1, AllData: []mms.Data{mms.Boolean(true)}}})
	return eth[22:]
}

// J.3.2.7.3.8-12: a tunnelled payload carries the destination MAC, the
// TPID and TCI as received (zero when not), and the Ethernet PDU from
// the ethertype; SV payloads carry the savPdu.
//
// Covers: SIG-IPE-1865
func TestRoutableTunnelAndSV(t *testing.T) {
	eth := unhex(t, c1Frame)
	b, err := EncodeRoutable(SPDU{SI: SITunnelled, Version: SessionVersion, Payloads: []Payload{
		{Tag: PayloadTunnel, APPID: 0x3001, Dst: net.HardwareAddr(eth[:6]), TPIDTCI: 0x81008005, APDU: eth[16:]},
		{Tag: PayloadTunnel, APPID: 0x3001, Dst: net.HardwareAddr(eth[:6]), APDU: eth[16:]}}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := DecodeRoutable(b)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := s.Frames()
	if err != nil || len(fs) != 2 {
		t.Fatalf("frames = %v, %v", fs, err)
	}
	if f := fs[0]; !f.Routable || f.VLAN != 5 || f.Priority != 4 || f.Dst.String() != "01:0c:cd:01:00:22" || f.GOOSE.SqNum != 3 || !f.Simulated {
		t.Errorf("tagged tunnel = %+v", f)
	}
	if f := fs[1]; f.VLAN != -1 || f.GOOSE.StNum != 2 {
		t.Errorf("untagged tunnel = %+v", f)
	}
	sv := EncodeSV(Frame{Dst: svDst, Src: src, VLAN: -1, APPID: 0x4000, SV: &SV{ASDUs: []ASDU{
		{SvID: "MU01", SmpCnt: 5, ConfRev: 1, SmpSynch: 2, SeqData: SeqData(make([]Sample, 8))}}}})
	b, err = EncodeRoutable(SPDU{SI: SISV, Version: SessionVersion, Payloads: []Payload{{Tag: PayloadSV, APPID: 0x4000, APDU: sv[22:]}}})
	if err != nil {
		t.Fatal(err)
	}
	s, _ = DecodeRoutable(b)
	if fs, err := s.Frames(); err != nil || len(fs) != 1 || fs[0].SV == nil || fs[0].SV.ASDUs[0].SmpCnt != 5 || fs[0].APPID != 0x4000 {
		t.Errorf("SV payload = %+v, %v", fs, err)
	}
	// The tunnel may not carry GSE management (J.3.2.7.3.8): a tunnelled
	// 88-B9 PDU is not a frame.
	mng := append([]byte{0x88, 0xb9}, eth[18:]...)
	b, _ = EncodeRoutable(SPDU{SI: SITunnelled, Version: SessionVersion, Payloads: []Payload{{Tag: PayloadTunnel, Dst: net.HardwareAddr(eth[:6]), APDU: mng}}})
	s, _ = DecodeRoutable(b)
	if _, err := s.Frames(); err == nil {
		t.Error("a tunnelled management PDU became a frame")
	}
}

// J.3.2.4 and J.3.3: the publisher's SPDUs carry SPDU numbers from 0,
// wrapping to 0; TTL is 32..254 and DSCP 0..63 (EF 46 by default).
//
// Covers: SIG-IPE-1866
func TestRoutablePublisherSink(t *testing.T) {
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	p := testPublication(t)
	p.UDPDst = ln.LocalAddr().String()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.ttl != 32 || p.dscp != 46 {
		t.Errorf("defaults ttl %d dscp %d", p.ttl, p.dscp)
	}
	u, err := openUDPSink(p)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	pub := NewPublisher(p)
	now := time.Unix(1_700_000_000, 0)
	frames := [][]byte{pub.Enable(now)}
	b, _ := pub.Due(pub.NextAt())
	frames = append(frames, b)
	for _, f := range frames {
		if err := u.WriteFrame(f); err != nil {
			t.Fatal(err)
		}
	}
	u.num = math.MaxUint32
	if err := u.WriteFrame(frames[0]); err != nil || u.num != 0 {
		t.Fatalf("after the maximum SPDU number: %d, %v", u.num, err)
	}
	_ = ln.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	for i, want := range []uint32{0, 1, math.MaxUint32} {
		n, err := ln.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		s, err := DecodeRoutable(buf[:n])
		if err != nil || s.SI != SIGOOSE || s.Number != want || s.KeyID != 0 {
			t.Fatalf("datagram %d = %+v, %v", i, s, err)
		}
		fs, err := s.Frames()
		if err != nil || fs[0].APPID != 0x3001 || fs[0].GOOSE.GoCBRef != p.GoCBRef {
			t.Errorf("datagram %d frames = %+v, %v", i, fs, err)
		}
	}
	for _, c := range []struct {
		ttl, dscp int
		udp       string
	}{{31, 46, "127.0.0.1"}, {255, 46, "127.0.0.1"}, {32, 64, "127.0.0.1"}, {32, 46, "nowhere:x"}, {32, 46, "::1"}} {
		q := testPublication(t)
		ttl, dscp := c.ttl, c.dscp
		q.TTL, q.DSCP, q.UDPDst = &ttl, &dscp, c.udp
		if err := q.Validate(); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	if !strings.Contains(p.udpDst.String(), "127.0.0.1") {
		t.Errorf("udpDst = %v", p.udpDst)
	}
	if a, err := udpTarget("239.1.2.3"); err != nil || a.Port != RoutablePort {
		t.Errorf("default port = %v, %v", a, err)
	}
}
