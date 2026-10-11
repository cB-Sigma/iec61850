// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package goose

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// afPacketSink sends frames through a raw AF_PACKET socket bound to one
// interface.
type afPacketSink struct {
	fd      atomic.Int32
	ifindex int
}

// OpenSendInterface opens the named interface for sending GOOSE (it needs
// CAP_NET_RAW) and returns its MAC address, the frames' default source.
func OpenSendInterface(name string) (Sink, net.HardwareAddr, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, fmt.Errorf("interface %s: %w", name, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return nil, nil, fmt.Errorf("opening a raw socket needs CAP_NET_RAW: %w", err)
		}
		return nil, nil, fmt.Errorf("opening a raw socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: ifi.Index}); err != nil {
		_ = unix.Close(fd)
		return nil, nil, fmt.Errorf("binding to %s: %w", name, err)
	}
	s := &afPacketSink{ifindex: ifi.Index}
	s.fd.Store(int32(fd))
	return s, ifi.HardwareAddr, nil
}

func (s *afPacketSink) WriteFrame(b []byte) error {
	fd := int(s.fd.Load())
	if fd < 0 {
		return errors.New("the interface was closed")
	}
	if len(b) < 14 {
		return errors.New("a frame shorter than an Ethernet header")
	}
	if len(b) < 60 {
		// Pad to the Ethernet minimum (8-1 Figure C.1 pad octets).
		b = append(b, make([]byte, 60-len(b))...)
	}
	to := &unix.SockaddrLinklayer{Ifindex: s.ifindex, Halen: 6}
	copy(to.Addr[:], b[:6])
	return unix.Sendto(fd, b, 0, to)
}

func (s *afPacketSink) Close() error {
	fd := s.fd.Swap(-1)
	if fd < 0 {
		return nil
	}
	return unix.Close(int(fd))
}
