// Package sv is the IEC 61850-9-2 Edition 2.1 (2011 + Amendment 1:2020)
// sampled values mapping onto ISO/IEC 8802-3: the Ethernet header with
// the IEEE 802.1Q tag (5.3.3.3), ethertype and APPID (5.3.3.4), the
// savPdu of Table 14 with the data set encoding of Tables 15 and 21, the
// MSVCB attributes of Tables 9, 10 and 20, the SCL address P-types of
// Table 19, the multicast recommendations of Annex B and a publisher
// (8.5.1 concatenation, clause 9 synchronisation).
//
// Every rule is taken from the clause named at the code, in our own
// words. IEC 62351-6 security (the extension after the APDU and the
// meaning of the savPdu security element) is not interpreted here: the
// header keeps the 28-bit reserved security word, the frame keeps the
// octets after the APDU and the savPdu keeps the security element raw.
package sv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// Link layer constants.
const (
	// EtherType of sampled values (Table 8).
	EtherType = 0x88BA
	// TPID of the IEEE 802.1Q tag (5.3.3.3, Figure 2).
	TPID = 0x8100
	// EtherTypeHSR is the IEC 62439-3 HSR tag (Figure A.2).
	EtherTypeHSR = 0x892F
	// PRPSuffix ends the IEC 62439-3 PRP trailer (Figure A.3).
	PRPSuffix = 0x88FB

	// APPIDType is the value of the two most significant APPID bits
	// for sampled values (Table 8: 0 1).
	APPIDType = 1
	// APPIDMin and APPIDMax bound the sampled values APPIDs; APPIDDefault
	// is sent when none is configured and marks a missing configuration
	// (5.3.3.4.2).
	APPIDMin     = 0x4000
	APPIDMax     = 0x7FFF
	APPIDDefault = 0x4000

	// DefaultVID and DefaultPriority apply when the configuration gives
	// none (Table 7).
	DefaultVID      = 0
	DefaultPriority = 4

	// HeaderLen is the Ethertype PDU header counted in Length: APPID,
	// Length, Reserved 1 and Reserved 2 (5.3.3.4.3).
	HeaderLen = 8
	// MaxAPDU is the largest m: Length is 8 + m with m below 1493
	// (5.3.3.4.3).
	MaxAPDU = 1492
	// SecurityMask covers the 28-bit reserved security word formed by
	// the low 12 bits of Reserved 1 and the 16 bits of Reserved 2
	// (5.3.3.4.5).
	SecurityMask = 0x0FFFFFFF
)

// ErrNotSV is returned for a frame of another ethertype.
var ErrNotSV = errors.New("sv: not a sampled values frame")

// HSRTag is the IEC 62439-3 HSR tag between the 802.1Q tag and the
// ethertype (Figure A.2): path and LSDU size, then the sequence number.
type HSRTag struct {
	PathSize uint16
	Seq      uint16
}

// PRPTrailer is the IEC 62439-3 redundancy control trailer at the end
// of the frame (Figure A.3): sequence number, LAN and LSDU size, then the
// suffix 0x88FB.
type PRPTrailer struct {
	Seq     uint16
	LanSize uint16
}

// Header is the link layer part of a sampled values frame.
type Header struct {
	Dst, Src net.HardwareAddr
	// Tagged: the frame carries the 802.1Q tag. A publisher always
	// sends it (5.3.3.3); a subscriber takes frames without it.
	Tagged   bool
	Priority uint8  // user priority, 0..7
	CFI      bool   // sent 0 (5.3.3.3); kept as received (F-1079)
	VID      uint16 // 0..4095
	HSR      *HSRTag
	APPID    uint16
	// Length is the Length field as received (8 + m); Encode computes it.
	Length uint16
	// Simulate is the S bit of Reserved 1 (Figure 3).
	Simulate bool
	// Reserved holds the three R bits of Reserved 1, sent 0.
	Reserved uint8
	// Security is the 28-bit word of the reserved security bits of
	// Reserved 1 (high 12 bits) and Reserved 2 (low 16 bits); 0 unless
	// the telegram is secured by IEC 62351-6 (5.3.3.4.5).
	Security uint32
}

// Reserved1 is the Reserved 1 field: S, R and the upper reserved
// security bits (Figure 3).
func (h Header) Reserved1() uint16 {
	r := uint16(h.Reserved&7)<<12 | uint16(h.Security>>16)&0x0FFF
	if h.Simulate {
		r |= 0x8000
	}
	return r
}

// Reserved2 is the Reserved 2 field (the lower reserved security bits).
func (h Header) Reserved2() uint16 { return uint16(h.Security) }

// APPIDInRange reports whether the APPID has the sampled values type
// (5.3.3.4.2, Table 8).
func (h Header) APPIDInRange() bool { return h.APPID>>14 == APPIDType }

// Frame is a decoded sampled values frame.
type Frame struct {
	Header
	// Offset is the index of APPID in the frame (18 when tagged, 24 with
	// an HSR tag, 14 untagged; Figures A.1 to A.3).
	Offset int
	// APDU is the m octets after Reserved 2.
	APDU []byte
	// Tail is what follows the APDU: the IEC 62351-6 extension, padding
	// and the PRP trailer (Figures A.1 to A.3), not interpreted here.
	Tail []byte
	// PRP is set when the frame ends in a PRP trailer.
	PRP *PRPTrailer
	// PDU is the decoded savPdu (nil from DecodeHeader).
	PDU *SavPDU
}

// DecodeHeader reads the link layer of b (destination MAC first, no
// FCS) and splits the APDU from the tail without decoding it.
func DecodeHeader(b []byte) (*Frame, error) {
	if len(b) < 14 {
		return nil, errors.New("sv: frame shorter than an Ethernet header")
	}
	f := &Frame{}
	f.Dst = net.HardwareAddr(append([]byte(nil), b[0:6]...))
	f.Src = net.HardwareAddr(append([]byte(nil), b[6:12]...))
	i := 12
	et := binary.BigEndian.Uint16(b[i:])
	i += 2
	if et == TPID {
		// 5.3.3.3: any VID and priority is taken; the tag is optional.
		if len(b) < i+4 {
			return nil, errors.New("sv: truncated 802.1Q tag")
		}
		tci := binary.BigEndian.Uint16(b[i:])
		f.Tagged = true
		f.Priority, f.CFI, f.VID = uint8(tci>>13), tci&0x1000 != 0, tci&0x0FFF
		et = binary.BigEndian.Uint16(b[i+2:])
		i += 4
	}
	if et == EtherTypeHSR {
		if len(b) < i+6 {
			return nil, errors.New("sv: truncated HSR tag")
		}
		f.HSR = &HSRTag{PathSize: binary.BigEndian.Uint16(b[i:]), Seq: binary.BigEndian.Uint16(b[i+2:])}
		et = binary.BigEndian.Uint16(b[i+4:])
		i += 6
	}
	if et != EtherType {
		return nil, ErrNotSV
	}
	if len(b) < i+HeaderLen {
		return nil, errors.New("sv: truncated Ethertype PDU header")
	}
	f.Offset = i
	f.APPID = binary.BigEndian.Uint16(b[i:])
	f.Length = binary.BigEndian.Uint16(b[i+2:])
	r1, r2 := binary.BigEndian.Uint16(b[i+4:]), binary.BigEndian.Uint16(b[i+6:])
	f.Simulate = r1&0x8000 != 0
	f.Reserved = uint8(r1>>12) & 7
	f.Security = uint32(r1&0x0FFF)<<16 | uint32(r2)
	// 5.3.3.4.3: Length is 8 + m with m < 1493; a frame whose Length is
	// below 8, above 1500 or beyond the frame is discarded.
	n := int(f.Length)
	if n < HeaderLen || n-HeaderLen > MaxAPDU || i+n > len(b) {
		return nil, fmt.Errorf("sv: Length %d does not fit the frame", n)
	}
	f.APDU = b[i+HeaderLen : i+n]
	f.Tail = b[i+n:]
	if t := f.Tail; len(t) >= 6 && binary.BigEndian.Uint16(t[len(t)-2:]) == PRPSuffix {
		f.PRP = &PRPTrailer{Seq: binary.BigEndian.Uint16(t[len(t)-6:]), LanSize: binary.BigEndian.Uint16(t[len(t)-4:])}
	}
	return f, nil
}

// Decode reads a sampled values frame and its savPdu.
func Decode(b []byte) (*Frame, error) {
	f, err := DecodeHeader(b)
	if err != nil {
		return nil, err
	}
	if f.PDU, err = DecodePDU(f.APDU); err != nil {
		return nil, err
	}
	return f, nil
}

// Encode builds a frame (no FCS, no padding) from h and the savPdu. The
// 802.1Q tag is written when h.Tagged, the HSR tag when h.HSR is set;
// Length is computed. The frame is refused when a field is out of range.
func Encode(h Header, p *SavPDU) ([]byte, error) {
	apdu, err := EncodePDU(p)
	if err != nil {
		return nil, err
	}
	return EncodeRaw(h, apdu)
}

// EncodeRaw is Encode with an APDU already encoded.
func EncodeRaw(h Header, apdu []byte) ([]byte, error) {
	if len(h.Dst) != 6 || len(h.Src) != 6 {
		return nil, errors.New("sv: MAC addresses must be 6 octets")
	}
	if h.Priority > 7 || h.VID > 0x0FFF || h.Reserved > 7 || h.Security&^SecurityMask != 0 {
		return nil, errors.New("sv: priority, VID, reserved or security bits out of range")
	}
	if len(apdu) > MaxAPDU {
		return nil, fmt.Errorf("sv: an APDU of %d octets exceeds %d (5.3.3.4.3)", len(apdu), MaxAPDU)
	}
	b := make([]byte, 0, 32+len(apdu))
	b = append(b, h.Dst...)
	b = append(b, h.Src...)
	if h.Tagged {
		tci := uint16(h.Priority)<<13 | h.VID
		if h.CFI {
			tci |= 0x1000
		}
		b = binary.BigEndian.AppendUint16(b, TPID)
		b = binary.BigEndian.AppendUint16(b, tci)
	}
	if h.HSR != nil {
		b = binary.BigEndian.AppendUint16(b, EtherTypeHSR)
		b = binary.BigEndian.AppendUint16(b, h.HSR.PathSize)
		b = binary.BigEndian.AppendUint16(b, h.HSR.Seq)
	}
	b = binary.BigEndian.AppendUint16(b, EtherType)
	b = binary.BigEndian.AppendUint16(b, h.APPID)
	b = binary.BigEndian.AppendUint16(b, uint16(HeaderLen+len(apdu)))
	b = binary.BigEndian.AppendUint16(b, h.Reserved1())
	b = binary.BigEndian.AppendUint16(b, h.Reserved2())
	return append(b, apdu...), nil
}
