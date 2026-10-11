package goose

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// Routable GOOSE and SV (IEC 61850-8-1 Ed. 2.1 Annex J): the GOOSE, SV
// or management APDUs, or whole tunnelled Ethernet PDUs, carried in a
// session PDU (SPDU) over UDP port 102 behind the two octets of RFC 1240
// connectionless transport (6.3.2.2: LI = 1 and the UD code only).
//
// KeyID 0 means neither HMAC nor encryption (J.3.2.1). The secured
// profile (a KeyID of a configured IEC 62351-6 key, the MAC after the
// payload, AES-GCM encryption of the payload) is in routable_sec.go.

// Session identifiers (J.3.2.2) and payload type tags (J.3.2.7.3.2).
const (
	SITunnelled = 0xA0
	SIGOOSE     = 0xA1
	SISV        = 0xA2
	SIMngt      = 0xA3

	PayloadGOOSE  = 0x81
	PayloadSV     = 0x82
	PayloadTunnel = 0x83
	PayloadMngt   = 0x84

	// RoutablePort is the UDP port of routable GOOSE and SV (6.3.3.2).
	RoutablePort = 102
	// SessionVersion is the session protocol version (J.3.2.5).
	SessionVersion = 2

	sessionPI       = 0x80  // common session header (J.3.2.2)
	maxSPDULength   = 64494 // J.3.2.3
	maxPayloadLen   = 64370 // J.3.2.7.2
	maxIVLength     = 233   // J.3.2.6
	paddingTag      = 0xAF  // J.3.2.7.4
	rfc1240LI       = 0x01
	rfc1240UD       = 0x40 // the UD TPDU code of ISO/IEC 8602
	sessionFixedLen = 4 + 4 + 2 + 4 + 2 + 4 + 1
)

// siPayload is the payload type each session identifier allows.
var siPayload = map[byte]byte{SITunnelled: PayloadTunnel, SIGOOSE: PayloadGOOSE, SISV: PayloadSV, SIMngt: PayloadMngt}

// SPDU is a routable GOOSE/SV session PDU.
type SPDU struct {
	SI               byte
	Number           uint32
	Version          uint16
	TimeOfCurrentKey uint32
	TimeOfNextKey    uint16
	KeyID            uint32
	IV               []byte
	Payloads         []Payload
}

// Payload is one user payload of an SPDU.
type Payload struct {
	Tag        byte
	Simulation bool
	APPID      uint16
	// APDU is the goosePdu, savPdu or mngtPdu; for a tunnelled payload,
	// the Ethernet PDU from the ethertype on (without the FCS).
	APDU []byte
	// Dst and TPIDTCI of a tunnelled payload (TPIDTCI 0 when the tag was
	// not received, J.3.2.7.3.10).
	Dst     net.HardwareAddr
	TPIDTCI uint32
}

// EncodeRoutable builds a UDP payload: the RFC 1240 octets and the
// SPDU, unsecured (KeyID 0, no IV, no padding, no HMAC).
func EncodeRoutable(s SPDU) ([]byte, error) {
	if _, ok := siPayload[s.SI]; !ok {
		return nil, fmt.Errorf("session identifier %#x", s.SI)
	}
	var user []byte
	for _, p := range s.Payloads {
		if p.Tag != siPayload[s.SI] {
			return nil, fmt.Errorf("payload %#x under session identifier %#x", p.Tag, s.SI)
		}
		user = append(user, p.Tag, b2o(p.Simulation))
		user = binary.BigEndian.AppendUint16(user, p.APPID)
		if p.Tag == PayloadTunnel {
			if len(p.Dst) != 6 {
				return nil, errors.New("a tunnelled payload needs a destination MAC")
			}
			user = append(user, p.Dst...)
			user = binary.BigEndian.AppendUint32(user, p.TPIDTCI)
		}
		if len(p.APDU) > 0xffff {
			return nil, errors.New("an APDU longer than 65535 octets")
		}
		user = binary.BigEndian.AppendUint16(user, uint16(len(p.APDU)))
		user = append(user, p.APDU...)
	}
	if len(user) > maxPayloadLen {
		return nil, fmt.Errorf("a payload of %d octets (at most %d)", len(user), maxPayloadLen)
	}
	pv := len(s.IV) + sessionFixedLen
	if len(s.IV) > maxIVLength {
		return nil, errors.New("an initialisation vector longer than 233 octets")
	}
	// SPDU Length: the octets after the length field itself (the
	// arithmetic of the J.3.2.3 note; see F-756).
	spduLen := pv - 4 + 4 + len(user)
	if spduLen > maxSPDULength {
		return nil, fmt.Errorf("an SPDU of %d octets (at most %d)", spduLen, maxSPDULength)
	}
	b := []byte{rfc1240LI, rfc1240UD, s.SI, byte(2 + pv), sessionPI, byte(pv)}
	b = binary.BigEndian.AppendUint32(b, uint32(spduLen))
	b = binary.BigEndian.AppendUint32(b, s.Number)
	b = binary.BigEndian.AppendUint16(b, s.Version)
	b = binary.BigEndian.AppendUint32(b, s.TimeOfCurrentKey)
	b = binary.BigEndian.AppendUint16(b, s.TimeOfNextKey)
	b = binary.BigEndian.AppendUint32(b, s.KeyID)
	b = append(b, byte(len(s.IV)))
	b = append(b, s.IV...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(user)))
	return append(b, user...), nil
}

func b2o(v bool) byte {
	if v {
		return 1
	}
	return 0
}

// ErrSecuredSPDU is returned for an SPDU with a KeyID other than 0 when
// no keys are configured.
var ErrSecuredSPDU = errors.New("a secured routable GOOSE/SV SPDU (KeyID other than 0) and no IEC 62351-6 keys")

// DecodeRoutable reads an unsecured UDP payload of routable GOOSE/SV.
// Octets after the payload (padding, an HMAC) are ignored.
func DecodeRoutable(b []byte) (*SPDU, error) {
	s, _, err := OpenRoutable(b, nil, time.Time{})
	return s, err
}

// OpenRoutable reads a UDP payload of routable GOOSE/SV. An SPDU with a
// KeyID other than 0 is verified (and decrypted) with the key of that ID
// in ks (see routable_sec.go); the FrameSec says which key and in what
// state. Unsecured SPDUs return a nil FrameSec.
func OpenRoutable(b []byte, ks *KeyStore, now time.Time) (*SPDU, *FrameSec, error) {
	if len(b) < 6 {
		return nil, nil, errors.New("a routable GOOSE/SV datagram shorter than its headers")
	}
	if b[0] != rfc1240LI || b[1] != rfc1240UD {
		return nil, nil, fmt.Errorf("not an RFC 1240 UD TPDU (%02x %02x)", b[0], b[1])
	}
	s := &SPDU{SI: b[2]}
	if _, ok := siPayload[s.SI]; !ok {
		return nil, nil, fmt.Errorf("unknown session identifier %#x", s.SI)
	}
	if b[4] != sessionPI {
		return nil, nil, fmt.Errorf("session header parameter %#x, want 0x80", b[4])
	}
	pv := int(b[5])
	h := b[6:]
	if pv < sessionFixedLen || len(h) < pv {
		return nil, nil, errors.New("a truncated session header")
	}
	spduLen := binary.BigEndian.Uint32(h)
	if spduLen > maxSPDULength {
		return nil, nil, fmt.Errorf("an SPDU length of %d (at most %d)", spduLen, maxSPDULength)
	}
	s.Number = binary.BigEndian.Uint32(h[4:])
	s.Version = binary.BigEndian.Uint16(h[8:])
	s.TimeOfCurrentKey = binary.BigEndian.Uint32(h[10:])
	s.TimeOfNextKey = binary.BigEndian.Uint16(h[14:])
	s.KeyID = binary.BigEndian.Uint32(h[16:])
	iv := int(h[20])
	if iv > maxIVLength || sessionFixedLen+iv > pv {
		return nil, nil, errors.New("an initialisation vector longer than its header")
	}
	s.IV = append([]byte(nil), h[21:21+iv]...)
	if s.Version != SessionVersion {
		return nil, nil, fmt.Errorf("session protocol version %d, want %d", s.Version, SessionVersion)
	}
	u := h[pv:]
	if len(u) < 4 {
		return nil, nil, errors.New("no payload length")
	}
	n := binary.BigEndian.Uint32(u)
	if n > maxPayloadLen || int(n) > len(u)-4 {
		return nil, nil, fmt.Errorf("a payload length of %d does not fit the SPDU", n)
	}
	p := u[4 : 4+n]
	var sec *FrameSec
	if s.KeyID != 0 {
		if ks == nil {
			return nil, nil, ErrSecuredSPDU
		}
		var err error
		if p, sec, err = ks.openSPDU(b, s, 6+pv+4, int(n), now); err != nil {
			return nil, sec, err
		}
	}
	want := siPayload[s.SI]
	for len(p) > 0 {
		if len(p) < 4 {
			return nil, sec, errors.New("a truncated payload")
		}
		pl := Payload{Tag: p[0], Simulation: p[1] != 0, APPID: binary.BigEndian.Uint16(p[2:])}
		if pl.Tag != want {
			return nil, sec, fmt.Errorf("payload %#x under session identifier %#x", pl.Tag, s.SI)
		}
		p = p[4:]
		if pl.Tag == PayloadTunnel {
			if len(p) < 10 {
				return nil, sec, errors.New("a truncated tunnelled payload")
			}
			pl.Dst = net.HardwareAddr(append([]byte(nil), p[:6]...))
			pl.TPIDTCI = binary.BigEndian.Uint32(p[6:])
			p = p[10:]
		}
		if len(p) < 2 {
			return nil, sec, errors.New("a truncated payload")
		}
		l := int(binary.BigEndian.Uint16(p))
		if l > len(p)-2 {
			return nil, sec, fmt.Errorf("an APDU length of %d does not fit the payload", l)
		}
		pl.APDU = append([]byte(nil), p[2:2+l]...)
		p = p[2+l:]
		s.Payloads = append(s.Payloads, pl)
	}
	return s, sec, nil
}

// Frames decodes the SPDU's GOOSE and SV payloads as frames: a GOOSE or
// SV payload has no MAC addresses (Dst and Src nil, VLAN -1) and is
// marked Routable; a tunnelled one is rebuilt as its Ethernet frame.
// Management payloads are skipped.
func (s *SPDU) Frames() ([]*Frame, error) {
	var out []*Frame
	for _, p := range s.Payloads {
		var f *Frame
		var err error
		switch p.Tag {
		case PayloadGOOSE:
			f = &Frame{VLAN: -1, EtherType: EtherTypeGOOSE, APPID: p.APPID, Simulated: p.Simulation}
			f.GOOSE, err = decodeGOOSE(p.APDU)
		case PayloadSV:
			f = &Frame{VLAN: -1, EtherType: EtherTypeSV, APPID: p.APPID, Simulated: p.Simulation}
			f.SV, err = decodeSV(p.APDU)
		case PayloadTunnel:
			eth := append(append([]byte(nil), p.Dst...), make([]byte, 6)...)
			if p.TPIDTCI != 0 {
				eth = binary.BigEndian.AppendUint32(eth, p.TPIDTCI)
			}
			f, err = Decode(append(eth, p.APDU...))
		default:
			continue
		}
		if err != nil {
			return out, err
		}
		f.Routable = true
		out = append(out, f)
	}
	return out, nil
}

// routableGOOSE turns one of our Ethernet GOOSE frames into a
// non-tunnelled routable GOOSE SPDU.
func routableGOOSE(eth []byte, number uint32) (SPDU, error) {
	i := 12
	if binary.BigEndian.Uint16(eth[i:]) == etherTypeVLAN {
		i += 4
	}
	if binary.BigEndian.Uint16(eth[i:]) != EtherTypeGOOSE {
		return SPDU{}, errors.New("not a GOOSE frame")
	}
	i += 2
	appid := binary.BigEndian.Uint16(eth[i:])
	length := int(binary.BigEndian.Uint16(eth[i+2:]))
	sim := eth[i+4]&0x80 != 0
	return SPDU{SI: SIGOOSE, Number: number, Version: SessionVersion,
		Payloads: []Payload{{Tag: PayloadGOOSE, Simulation: sim, APPID: appid, APDU: eth[i+8 : i+length]}}}, nil
}
