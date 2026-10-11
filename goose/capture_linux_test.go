// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package goose

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cB-Sigma/iec61850/mms"
)

// Covers: SIG-IPE-365
func TestLoopbackCapture(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("no loopback interface: %v", err)
	}
	dst := net.HardwareAddr{0x01, 0x0c, 0xcd, 0x01, 0x00, 0x42}
	src, err := OpenInterface("lo", []net.HardwareAddr{dst})
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("raw sockets need CAP_NET_RAW here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	tx, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		t.Skipf("no raw socket to send with: %v", err)
	}
	defer unix.Close(tx)
	frame := EncodeGOOSE(Frame{Dst: dst, Src: net.HardwareAddr{2, 0, 0, 0, 0, 1}, VLAN: -1, APPID: 0x0042, GOOSE: &GOOSE{
		GoCBRef: "LOOP/LLN0$GO$gcb", TAL: time.Second, DatSet: "LOOP/LLN0$DS", StNum: 3, SqNum: 1, ConfRev: 1,
		T: time.Now(), AllData: []mms.Data{mms.Boolean(true)}}})
	// Unrelated traffic on lo (IPv4) never passes the filter.
	other := append([]byte(nil), frame...)
	other[12], other[13] = 0x08, 0x00
	to := &unix.SockaddrLinklayer{Ifindex: lo.Index, Halen: 6}
	copy(to.Addr[:], dst)
	done := make(chan *Frame, 1)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := src.ReadFrame(buf)
			if err != nil {
				close(done)
				return
			}
			if f, err := Decode(buf[:n]); err == nil && f.APPID == 0x0042 {
				done <- f
				return
			}
		}
	}()
	deadline := time.After(5 * time.Second)
	for {
		_ = unix.Sendto(tx, other, 0, to)
		if err := unix.Sendto(tx, frame, 0, to); err != nil {
			t.Fatalf("sending on lo: %v", err)
		}
		select {
		case f, ok := <-done:
			if !ok {
				t.Fatal("the capture ended")
			}
			if f.GOOSE.GoCBRef != "LOOP/LLN0$GO$gcb" || f.GOOSE.StNum != 3 {
				t.Errorf("captured %+v", f.GOOSE)
			}
			return
		case <-deadline:
			t.Fatal("no GOOSE frame captured on lo")
		case <-time.After(100 * time.Millisecond):
		}
	}
}
