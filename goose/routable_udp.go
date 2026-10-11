// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package goose

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	"golang.org/x/net/ipv4"
)

// Routable publishing defaults (IEC 61850-8-1 J.3.3).
const (
	DefaultTTL  = 32 // at least 32, never 255
	DefaultDSCP = 46 // Expedited Forwarding, RFC 3246

	defaultTTL  = DefaultTTL
	defaultDSCP = DefaultDSCP
)

// UDPTarget resolves a publication's UDPDst ("ip" or "ip:port"; port
// RoutablePort by default).
func UDPTarget(s string) (*net.UDPAddr, error) {
	host, port := s, strconv.Itoa(RoutablePort)
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	}
	a, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, port))
	if err != nil || a.IP.To4() == nil {
		return nil, fmt.Errorf("udpDst %q is not an IPv4 address with an optional port", s)
	}
	return a, nil
}

func udpTarget(s string) (*net.UDPAddr, error) { return UDPTarget(s) }

// DialRoutable opens the UDP socket of a validated publication with a
// UDPDst, with its TTL (also as multicast TTL) and DSCP set (J.3.3).
func DialRoutable(p *Publication) (*net.UDPConn, error) {
	if p.udpDst == nil {
		return nil, errors.New("the publication has no validated udpDst")
	}
	conn, err := net.DialUDP("udp4", nil, p.udpDst)
	if err != nil {
		return nil, fmt.Errorf("udpDst %s: %w", p.UDPDst, err)
	}
	c := ipv4.NewConn(conn)
	pc := ipv4.NewPacketConn(conn)
	errs := []error{c.SetTTL(p.ttl), c.SetTOS(p.dscp << 2)}
	if p.udpDst.IP.IsMulticast() {
		errs = append(errs, pc.SetMulticastTTL(p.ttl))
	}
	if err := errors.Join(errs...); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("setting TTL and DSCP: %w", err)
	}
	return conn, nil
}

// RoutableGOOSE wraps an Ethernet GOOSE frame as the routable GOOSE SPDU
// with the given SPDU number (J.3.2.4).
func RoutableGOOSE(eth []byte, number uint32) (SPDU, error) { return routableGOOSE(eth, number) }

// UDPSink sends a publication's frames as routable GOOSE SPDUs (J.3.2):
// the SPDU number starts at 0 and wraps to 0 (J.3.2.4; one destination
// per publication). It is a Sink.
type UDPSink struct {
	mu   sync.Mutex
	conn *net.UDPConn
	num  uint32
	// Seal, when set, secures each SPDU (IEC 62351-6: SealRoutable under
	// the application's current key); nil sends them unsecured.
	Seal func(SPDU) ([]byte, error)
}

// OpenUDPSink opens the routable sink of a validated publication with a
// UDPDst (DialRoutable).
func OpenUDPSink(p *Publication) (*UDPSink, error) {
	conn, err := DialRoutable(p)
	if err != nil {
		return nil, err
	}
	return &UDPSink{conn: conn}, nil
}

func openUDPSink(p *Publication) (*UDPSink, error) { return OpenUDPSink(p) }

// WriteFrame sends one Ethernet GOOSE frame as the next SPDU.
func (u *UDPSink) WriteFrame(eth []byte) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	s, err := routableGOOSE(eth, u.num)
	if err != nil {
		return err
	}
	var b []byte
	if u.Seal != nil {
		b, err = u.Seal(s)
	} else {
		b, err = EncodeRoutable(s)
	}
	if err != nil {
		return err
	}
	if _, err := u.conn.Write(b); err != nil {
		return err
	}
	u.num++ // wraps to 0
	return nil
}

// Close closes the socket.
func (u *UDPSink) Close() error { return u.conn.Close() }
