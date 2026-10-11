// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package goose

import "net"

// OpenInterface captures GOOSE and sampled values on a network interface;
// it needs Linux (AF_PACKET) and returns ErrNotSupported elsewhere.
func OpenInterface(name string, _ []net.HardwareAddr) (Source, error) {
	return nil, ErrNotSupported
}

// OpenSendInterface sends frames on a network interface; it needs Linux
// (AF_PACKET) and returns ErrNotSupported elsewhere.
func OpenSendInterface(string) (Sink, net.HardwareAddr, error) {
	return nil, nil, ErrNotSupported
}
