// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package goose

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// afPacket reads frames from a raw AF_PACKET socket bound to one
// interface. A classic BPF filter passes GOOSE, SV and 802.1Q frames
// only, so the station bus's other traffic never reaches user space.
type afPacket struct {
	fd  atomic.Int32 // -1 once closed
	oob [64]byte     // control messages; ReadFrame is called from one goroutine
}

// auxVLAN returns the 802.1Q tag the kernel stripped, from the
// PACKET_AUXDATA control message.
func auxVLAN(oob []byte) (tpid, tci uint16, ok bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, 0, false
	}
	for _, m := range msgs {
		if m.Header.Level != unix.SOL_PACKET || m.Header.Type != unix.PACKET_AUXDATA || len(m.Data) < int(unsafe.Sizeof(unix.TpacketAuxdata{})) {
			continue
		}
		aux := (*unix.TpacketAuxdata)(unsafe.Pointer(&m.Data[0]))
		if aux.Status&unix.TP_STATUS_VLAN_VALID == 0 {
			return 0, 0, false
		}
		tpid = EtherTypeVLAN
		if aux.Status&unix.TP_STATUS_VLAN_TPID_VALID != 0 {
			tpid = aux.Vlan_tpid
		}
		return tpid, aux.Vlan_tci, true
	}
	return 0, 0, false
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// filter: load the ethertype at offset 12; accept 0x88B8, 0x88BA, 0x8100
// (VLAN tags the kernel did not strip) and 0x892F (an HSR tag, 8-1
// Figure C.2); drop the rest.
var rawFilter = []unix.SockFilter{
	{Code: 0x28, K: 12},                           // ldh [12]
	{Code: 0x15, Jt: 4, Jf: 0, K: EtherTypeGOOSE}, // jeq #0x88b8, accept
	{Code: 0x15, Jt: 3, Jf: 0, K: EtherTypeSV},    // jeq #0x88ba, accept
	{Code: 0x15, Jt: 2, Jf: 0, K: EtherTypeVLAN},  // jeq #0x8100, accept
	{Code: 0x15, Jt: 1, Jf: 0, K: EtherTypeHSR},   // jeq #0x892f, accept
	{Code: 0x06, K: 0},                            // ret #0
	{Code: 0x06, K: 0x40000},                      // ret #262144
}

// OpenInterface opens a raw capture on the named interface (it needs
// CAP_NET_RAW) and joins the multicast groups of macs; with no MAC it
// receives every multicast frame.
func OpenInterface(name string, macs []net.HardwareAddr) (Source, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", name, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return nil, fmt.Errorf("opening a raw socket needs CAP_NET_RAW: %w", err)
		}
		return nil, fmt.Errorf("opening a raw socket: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = unix.Close(fd)
		}
	}()
	prog := unix.SockFprog{Len: uint16(len(rawFilter)), Filter: &rawFilter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		return nil, fmt.Errorf("attaching the frame filter: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		return nil, fmt.Errorf("binding to %s: %w", name, err)
	}
	if len(macs) == 0 {
		mr := unix.PacketMreq{Ifindex: int32(ifi.Index), Type: unix.PACKET_MR_ALLMULTI}
		if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mr); err != nil {
			return nil, fmt.Errorf("receiving all multicast on %s: %w", name, err)
		}
	}
	for _, m := range macs {
		mr := unix.PacketMreq{Ifindex: int32(ifi.Index), Type: unix.PACKET_MR_MULTICAST, Alen: 6}
		copy(mr.Address[:], m)
		if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mr); err != nil {
			return nil, fmt.Errorf("joining %s on %s: %w", m, name, err)
		}
	}
	// The driver usually strips the 802.1Q tag; the auxiliary data carries
	// it so that ReadFrame can restore it for VLAN filtering.
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_AUXDATA, 1); err != nil {
		return nil, fmt.Errorf("asking for packet auxiliary data: %w", err)
	}
	// A receive timeout lets Close end a blocked read.
	tv := unix.Timeval{Usec: 200000}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, err
	}
	ok = true
	a := &afPacket{}
	a.fd.Store(int32(fd))
	return a, nil
}

var errClosed = errors.New("the capture was closed")

func (a *afPacket) ReadFrame(buf []byte) (int, time.Time, error) {
	for {
		fd := int(a.fd.Load())
		if fd < 0 {
			return 0, time.Time{}, errClosed
		}
		// Leave four bytes spare for a tag restored from the auxiliary data.
		room := len(buf)
		if room > 18 {
			room -= 4
		}
		n, oobn, _, from, err := unix.Recvmsg(fd, buf[:room], a.oob[:], 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) {
				return 0, time.Time{}, errClosed
			}
			return 0, time.Time{}, err
		}
		// Our own transmissions come back as outgoing copies.
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		if tpid, tci, ok := auxVLAN(a.oob[:oobn]); ok {
			n = InsertVLANTag(buf, n, tpid, tci)
		}
		return n, time.Now(), nil
	}
}

func (a *afPacket) Close() error {
	fd := a.fd.Swap(-1)
	if fd < 0 {
		return nil
	}
	return unix.Close(int(fd))
}
