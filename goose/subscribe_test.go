// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package goose

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

func subFrame(t *testing.T, mod func(*GOOSE)) *Frame {
	t.Helper()
	g := &GOOSE{GoCBRef: "BAY1/LLN0$GO$gcb01", TAL: 100 * time.Millisecond, DatSet: "BAY1/LLN0$DS", GoID: "g1", StNum: 1, SqNum: 0,
		ConfRev: 3, T: time.Now(), AllData: []mms.Data{mms.Boolean(true), mms.Boolean(false)}}
	if mod != nil {
		mod(g)
	}
	b := EncodeGOOSE(Frame{Dst: net.HardwareAddr{1, 0x0c, 0xcd, 1, 0, 1}, Src: net.HardwareAddr{2, 0, 0, 0, 0, 1}, VLAN: -1, APPID: 1, GOOSE: g})
	f, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestSubscription: a subscriber takes messages of its control block and
// configuration, classifies them, refuses the wrong control block, data
// set, confRev, entry count, NdsCom and (outside test mode) simulation,
// and sees the stream expire after the time allowed to live.
func TestSubscription(t *testing.T) {
	s := &Subscription{GoCBRef: "BAY1/LLN0$GO$gcb01", DatSet: "BAY1/LLN0$DS", ConfRev: 3, Entries: 2}
	t0 := time.Now()
	if a, _, err := s.Accept(subFrame(t, nil), t0); err != nil || a != ArrivalFirst {
		t.Fatalf("first: %v %v", a, err)
	}
	if a, _, err := s.Accept(subFrame(t, func(g *GOOSE) { g.SqNum = 1 }), t0.Add(10*time.Millisecond)); err != nil || a != ArrivalRetransmission {
		t.Fatalf("retransmission: %v %v", a, err)
	}
	if a, lost, err := s.Accept(subFrame(t, func(g *GOOSE) { g.StNum = 3 }), t0.Add(20*time.Millisecond)); err != nil || a != ArrivalNewState || !lost {
		t.Fatalf("new state after a lost one: %v %v %v", a, lost, err)
	}
	if a, _, _ := s.Accept(subFrame(t, func(g *GOOSE) { g.StNum = 2 }), t0.Add(25*time.Millisecond)); a != ArrivalOld {
		t.Errorf("late message: %v", a)
	}
	if s.Expired(t0.Add(100 * time.Millisecond)) {
		t.Error("expired within TAL")
	}
	if !s.Expired(t0.Add(200 * time.Millisecond)) {
		t.Error("not expired after TAL")
	}
	for name, c := range map[string]struct {
		mod  func(*GOOSE)
		want error
	}{
		"control block": {func(g *GOOSE) { g.GoCBRef = "BAY1/LLN0$GO$other" }, ErrOtherControlBlock},
		"data set":      {func(g *GOOSE) { g.DatSet = "BAY1/LLN0$DS2" }, ErrConfiguration},
		"confRev":       {func(g *GOOSE) { g.ConfRev = 4 }, ErrConfiguration},
		"entries":       {func(g *GOOSE) { g.AllData = g.AllData[:1] }, ErrConfiguration},
		"ndsCom":        {func(g *GOOSE) { g.NdsCom = true }, ErrNeedsCommissioning},
		"simulation":    {func(g *GOOSE) { g.Simulation = true }, ErrSimulated},
	} {
		if _, _, err := s.Accept(subFrame(t, c.mod), t0); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	s.AcceptSimulated = true
	if _, _, err := s.Accept(subFrame(t, func(g *GOOSE) { g.Simulation = true; g.StNum = 4 }), t0); err != nil {
		t.Errorf("simulated message in test mode: %v", err)
	}
}
