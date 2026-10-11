package goose

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cB-Sigma/iec61850/goose/sv"
	"github.com/cB-Sigma/iec61850/mms"
)

// Ethertypes of IEC 61850-8-1 GOOSE and IEC 61850-9-2 sampled values.
const (
	EtherTypeGOOSE = 0x88B8
	EtherTypeSV    = 0x88BA
	// EtherTypeMngt carries GSE and SV management (IEC 61850-8-1 Table
	// C.2); this package neither sends nor answers it.
	EtherTypeMngt = 0x88B9
	// EtherTypeVLAN is the IEEE 802.1Q tag.
	EtherTypeVLAN = 0x8100
	etherTypeVLAN = EtherTypeVLAN
	// etherTypeHSR is the IEC 62439-3 HSR tag, which 8-1 Figure C.2 puts
	// between the 802.1Q tag and the GOOSE ethertype.
	etherTypeHSR = 0x892F
	// EtherTypeHSR is the IEC 62439-3 HSR tag.
	EtherTypeHSR = etherTypeHSR
	// maxAPDU: the length field is 8 + m with m below 1492 (8-1 C.2.5).
	maxAPDU = 1491
)

// Frame is a decoded Ethernet frame carrying GOOSE or SV.
type Frame struct {
	Dst, Src  net.HardwareAddr
	VLAN      int // VLAN ID, -1 when untagged
	Priority  int // 802.1Q priority
	EtherType uint16
	APPID     uint16
	// Simulated is the S bit of Reserved 1 (IEC 61850-8-1 Figure C.5).
	Simulated bool
	// Reserved1 (without the S bit) and Reserved2 hold the three reserved
	// bits and the IEC 62351-6 security fields (the extension length and
	// the CRC of octets 1 to 8, read into Sec).
	Reserved1, Reserved2 uint16
	// HSR is set when the frame carried an IEC 62439-3 HSR tag.
	HSR bool
	// Sec is the IEC 62351-6 extension, or the verified routable SPDU's
	// key; nil for an unsecured frame.
	Sec *FrameSec
	// Routable is set for a frame received as routable GOOSE/SV over UDP
	// (8-1 Annex J); a non-tunnelled one has no MAC addresses.
	Routable bool
	GOOSE    *GOOSE // for EtherTypeGOOSE
	SV       *SV    // for EtherTypeSV
}

// GOOSE is a decoded goosePdu.
type GOOSE struct {
	GoCBRef string
	TAL     time.Duration // timeAllowedtoLive
	DatSet  string
	GoID    string
	T       time.Time
	// TQuality is the time quality octet of t (8-1 Table 36): leap
	// second known, clock failure, clock not synchronised, accuracy.
	TQuality   byte
	StNum      uint32
	SqNum      uint32
	Simulation bool // test / simulation flag of the PDU
	ConfRev    uint32
	NdsCom     bool
	NumEntries int
	AllData    []mms.Data
}

// SV is a decoded savPdu.
type SV struct {
	ASDUs []ASDU
	// SecurityT is the timestamp of the savPdu security field (IEC
	// 62351-6 6.2.2.2), zero when the field is absent.
	SecurityT time.Time
}

// ASDU is one sampled value ASDU.
type ASDU struct {
	SvID     string
	DatSet   string
	SmpCnt   uint16
	ConfRev  uint32
	RefrTm   time.Time
	SmpSynch int // 0 none, 1 local, 2 global
	SmpRate  int // samples per nominal period or per second, when sent
	SeqData  []byte
	SmpMod   int
	// SmpModSet: smpMod was present (decoding) or is sent (encoding).
	SmpModSet bool
	// GmIdentity is the PTP grandmaster identity (9-2 Table 14), nil when
	// absent.
	GmIdentity *[8]byte
}

// InsertVLANTag puts an IEEE 802.1Q tag (tpid, 0x8100 when zero, and
// tci) back after the source MAC of the n-byte frame in buf, as a capture
// that had the tag stripped by the network driver must do before
// decoding. It returns the new length, or n unchanged when the frame is
// too short, already tagged, or buf has no room for four more bytes.
func InsertVLANTag(buf []byte, n int, tpid, tci uint16) int {
	if n < 14 || n+4 > len(buf) {
		return n
	}
	if et := binary.BigEndian.Uint16(buf[12:]); et == etherTypeVLAN || et == 0x88a8 {
		return n
	}
	if tpid == 0 {
		tpid = etherTypeVLAN
	}
	copy(buf[16:n+4], buf[12:n])
	binary.BigEndian.PutUint16(buf[12:], tpid)
	binary.BigEndian.PutUint16(buf[14:], tci)
	return n + 4
}

// ErrNotGOOSEorSV is returned for frames of another ethertype.
var ErrNotGOOSEorSV = errors.New("not a GOOSE or sampled values frame")

// Decode decodes an Ethernet frame (destination MAC first, no FCS).
func Decode(b []byte) (*Frame, error) {
	if len(b) < 14 {
		return nil, errors.New("frame shorter than an Ethernet header")
	}
	f := &Frame{Dst: net.HardwareAddr(append([]byte(nil), b[0:6]...)), Src: net.HardwareAddr(append([]byte(nil), b[6:12]...)), VLAN: -1}
	i := 12
	et := binary.BigEndian.Uint16(b[i:])
	i += 2
	if et == etherTypeVLAN {
		if len(b) < i+4 {
			return nil, errors.New("truncated 802.1Q tag")
		}
		tci := binary.BigEndian.Uint16(b[i:])
		f.Priority, f.VLAN = int(tci>>13), int(tci&0x0fff)
		et = binary.BigEndian.Uint16(b[i+2:])
		i += 4
	}
	if et == etherTypeHSR {
		// Path/size and sequence number (4 octets), then the ethertype.
		if len(b) < i+6 {
			return nil, errors.New("truncated HSR tag")
		}
		f.HSR = true
		et = binary.BigEndian.Uint16(b[i+4:])
		i += 6
	}
	f.EtherType = et
	if et != EtherTypeGOOSE && et != EtherTypeSV {
		return nil, ErrNotGOOSEorSV
	}
	if len(b) < i+8 {
		return nil, errors.New("truncated APPID header")
	}
	f.APPID = binary.BigEndian.Uint16(b[i:])
	length := int(binary.BigEndian.Uint16(b[i+2:]))
	res1 := binary.BigEndian.Uint16(b[i+4:])
	f.Simulated = res1&0x8000 != 0
	f.Reserved1, f.Reserved2 = res1&0x7fff, binary.BigEndian.Uint16(b[i+6:])
	limit := maxAPDU
	if et == EtherTypeSV {
		limit = sv.MaxAPDU // 9-2 5.3.3.4.3: m < 1493 (F-1080)
	}
	if length < 8 || length-8 > limit || i+length > len(b) {
		return nil, fmt.Errorf("the length field (%d) does not fit the frame", length)
	}
	apdu := b[i+8 : i+length]
	// IEC 62351-6 8.2.1: a non-zero security extension length in
	// Reserved 1 announces the extension after the APDU.
	// A subscriber that does not expect it ignores it (62351-6 6.2.1.2,
	// 8-1 C.2.5), so one that does not fit is only marked malformed.
	if n := int(f.Reserved1 & maxExtension); n > 0 {
		if i+length+n > len(b) {
			f.Sec = &FrameSec{ExtLen: n, Malformed: fmt.Sprintf("the security extension (%d octets) does not fit the frame", n)}
		} else {
			f.Sec = parseExtension(b[i-2:i+length], b[i+length:i+length+n])
			f.Sec.CRCOK = crc16(b[i-2:i+6]) == f.Reserved2
		}
	}
	var err error
	if et == EtherTypeGOOSE {
		f.GOOSE, err = decodeGOOSE(apdu)
	} else {
		f.SV, err = decodeSV(apdu)
	}
	if err != nil {
		return nil, err
	}
	return f, nil
}

func uintOf(v []byte) (uint32, error) {
	if len(v) == 0 || len(v) > 5 || (len(v) == 5 && v[0] != 0) {
		return 0, errors.New("an unsigned integer of bad length")
	}
	var n uint32
	for _, c := range v {
		n = n<<8 | uint32(c)
	}
	return n, nil
}

func boolOf(v []byte) bool { return len(v) == 1 && v[0] != 0 }

func decodeGOOSE(apdu []byte) (*GOOSE, error) {
	e, _, err := mms.Parse(apdu)
	if err != nil {
		return nil, fmt.Errorf("goosePdu: %w", err)
	}
	if e.Tag != 0x61 {
		return nil, fmt.Errorf("goosePdu has tag %#x, want 0x61", e.Tag)
	}
	kids, err := e.Children()
	if err != nil {
		return nil, fmt.Errorf("goosePdu: %w", err)
	}
	g := &GOOSE{}
	seen := map[int]bool{}
	for _, k := range kids {
		if k.Tag&0xc0 != 0x80 {
			continue
		}
		seen[k.Num] = true
		var err error
		var n uint32
		switch k.Num {
		case 0:
			g.GoCBRef = string(k.Val)
		case 1:
			n, err = uintOf(k.Val)
			g.TAL = time.Duration(n) * time.Millisecond
		case 2:
			g.DatSet = string(k.Val)
		case 3:
			g.GoID = string(k.Val)
		case 4:
			var u mms.UTCTime
			u, err = mms.DecodeUTCTime(k.Val)
			g.T, g.TQuality = u.T, u.Quality
		case 5:
			g.StNum, err = uintOf(k.Val)
		case 6:
			g.SqNum, err = uintOf(k.Val)
		case 7:
			g.Simulation = boolOf(k.Val)
		case 8:
			g.ConfRev, err = uintOf(k.Val)
		case 9:
			g.NdsCom = boolOf(k.Val)
		case 10:
			n, err = uintOf(k.Val)
			g.NumEntries = int(n)
		case 11:
			var items []mms.Elem
			if items, err = k.Children(); err == nil {
				for _, it := range items {
					d, derr := decodeGOOSEData(it)
					if derr != nil {
						return nil, fmt.Errorf("goosePdu allData: %w", derr)
					}
					g.AllData = append(g.AllData, d)
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("goosePdu field %d: %w", k.Num, err)
		}
	}
	for _, n := range []int{0, 1, 2, 4, 5, 6, 8, 10, 11} {
		if !seen[n] {
			return nil, fmt.Errorf("goosePdu lacks mandatory field %d", n)
		}
	}
	if g.NumEntries != len(g.AllData) {
		return nil, fmt.Errorf("goosePdu announces %d entries and carries %d", g.NumEntries, len(g.AllData))
	}
	return g, nil
}

// decodeSV reads a savPdu with the IEC 61850-9-2 Ed. 2.1 codec (package
// sv); the IEC 62351-6 security timestamp stays read here.
func decodeSV(apdu []byte) (*SV, error) {
	p, err := sv.DecodePDU(apdu)
	if err != nil {
		return nil, err
	}
	out := &SV{}
	// security [1] ANY OPTIONAL holding [0] IMPLICIT SEQUENCE
	// {timestamp [0] IMPLICIT OCTET STRING, ...} (62351-6 6.2.2.2); a
	// timestamp directly inside [1] is also read (F-812). A primitive
	// [1] (9-2 Figure A.6, F-1071) carries no timestamp.
	if len(p.Security) > 0 && p.Security[0] == 0xa1 {
		e, _, err := mms.Parse(p.Security)
		if err == nil {
			out.SecurityT, err = svSecurityTime(e)
		}
		if err != nil {
			return nil, fmt.Errorf("savPdu security: %w", err)
		}
	}
	for _, a := range p.ASDUs {
		x := ASDU{SvID: a.SvID, SmpCnt: a.SmpCnt, ConfRev: a.ConfRev, SmpSynch: int(a.SmpSynch), SeqData: a.Sample, GmIdentity: a.GmIdentity}
		if a.DatSet != nil {
			x.DatSet = *a.DatSet
		}
		if t := a.RefrTm; t != nil && (t.Seconds != 0 || t.Fraction != 0) {
			x.RefrTm = t.Time()
		}
		if a.SmpRate != nil {
			x.SmpRate = int(*a.SmpRate)
		}
		if a.SmpMod != nil {
			x.SmpMod, x.SmpModSet = int(*a.SmpMod), true
		}
		out.ASDUs = append(out.ASDUs, x)
	}
	return out, nil
}

func svSecurityTime(e mms.Elem) (time.Time, error) {
	kids, err := e.Children()
	if err != nil {
		return time.Time{}, err
	}
	for _, k := range kids {
		if k.Tag == 0xa0 {
			if kids, err = k.Children(); err != nil {
				return time.Time{}, err
			}
			break
		}
	}
	for _, k := range kids {
		if k.Tag == 0x80 {
			u, err := mms.DecodeUTCTime(k.Val)
			return u.T, err
		}
	}
	return time.Time{}, errors.New("no timestamp")
}

// Sample is one channel value of an ASDU's sequence of data: a 32-bit
// value and its 32-bit quality (the IEC 61850-9-2 LE layout).
type Sample struct {
	Value   int32
	Quality uint32
	// real is the member value when it came from a typed data set
	// (SVSub.dataTypes), which may not fit an int32.
	real    float64
	hasReal bool
}

// RealSample is a sample carrying a member value that may not fit an
// int32 (a typed data set member); Value holds it clamped.
func RealSample(v float64, value int32, quality uint32) Sample {
	return Sample{Value: value, Quality: quality, real: v, hasReal: true}
}

// Float is the sample's value as a number.
func (s Sample) Float() float64 {
	if s.hasReal {
		return s.real
	}
	return float64(s.Value)
}

// Samples splits sequence of data into value/quality pairs.
func (a ASDU) Samples() ([]Sample, error) {
	if len(a.SeqData)%8 != 0 {
		return nil, fmt.Errorf("sequence of data of %d octets is not value/quality pairs", len(a.SeqData))
	}
	out := make([]Sample, len(a.SeqData)/8)
	for i := range out {
		out[i].Value = int32(binary.BigEndian.Uint32(a.SeqData[i*8:]))
		out[i].Quality = binary.BigEndian.Uint32(a.SeqData[i*8+4:])
	}
	return out, nil
}

// SampleQuality names a sample's quality by IEC 61850-9-2 Table 21:
// validity from the two low bits (0 good, 2 invalid, 1 the formerly
// reserved value read as invalid, 3 questionable), then the flags.
func SampleQuality(q uint32) string { return sv.Quality(q).String() }

// ---- encoders (for tests, simulators and replay files) ---------------------

func be(n uint32) []byte {
	return mms.UintBytes(uint64(n))
}

func ethernet(dst, src net.HardwareAddr, vlan int, prio int, et uint16, appid uint16, simulated bool, apdu []byte) []byte {
	b := make([]byte, 0, 26+len(apdu))
	b = append(b, dst...)
	b = append(b, src...)
	if vlan >= 0 {
		b = binary.BigEndian.AppendUint16(b, etherTypeVLAN)
		b = binary.BigEndian.AppendUint16(b, uint16(prio)<<13|uint16(vlan&0x0fff))
	}
	b = binary.BigEndian.AppendUint16(b, et)
	b = binary.BigEndian.AppendUint16(b, appid)
	b = binary.BigEndian.AppendUint16(b, uint16(8+len(apdu)))
	var r1 uint16
	if simulated {
		r1 = 0x8000
	}
	b = binary.BigEndian.AppendUint16(b, r1)
	b = binary.BigEndian.AppendUint16(b, 0)
	return append(b, apdu...)
}

// EncodeGOOSE builds a GOOSE frame with the BER encoding (8-1 A.2); the
// publisher and the tests use it. The fixed-length encoding (A.3) is
// optional (A.4) and is decoded, not sent.
func EncodeGOOSE(f Frame) []byte {
	g := f.GOOSE
	// goID is not OPTIONAL in the Ed. 2.1 grammar (8-1 A.1), so it is
	// always sent.
	parts := [][]byte{
		mms.Str(0x80, g.GoCBRef), mms.T(0x81, be(uint32(g.TAL/time.Millisecond))), mms.Str(0x82, g.DatSet), mms.Str(0x83, g.GoID),
	}
	data := make([][]byte, len(g.AllData))
	for i, d := range g.AllData {
		data[i] = d.Encode()
	}
	parts = append(parts, mms.T(0x84, mms.UTCTime{T: g.T, Quality: g.TQuality}.Encode()),
		mms.T(0x85, be(g.StNum)), mms.T(0x86, be(g.SqNum)), mms.Bool(0x87, g.Simulation),
		mms.T(0x88, be(g.ConfRev)), mms.Bool(0x89, g.NdsCom), mms.T(0x8a, be(uint32(len(g.AllData)))),
		mms.T(0xab, data...))
	return ethernet(f.Dst, f.Src, f.VLAN, f.Priority, EtherTypeGOOSE, f.APPID, f.Simulated, mms.T(0x61, parts...))
}

// EncodeSV builds a sampled values frame with the IEC 61850-9-2 codec
// (package sv); it returns nil for a savPdu the grammar refuses (no
// ASDU, an empty or overlong svID).
func EncodeSV(f Frame) []byte {
	p := &sv.SavPDU{}
	if !f.SV.SecurityT.IsZero() {
		p.Security = mms.T(0xa1, mms.T(0xa0, mms.T(0x80, mms.UTCTime{T: f.SV.SecurityT, Quality: 0x0a}.Encode())))
	}
	for _, a := range f.SV.ASDUs {
		x := sv.ASDU{SvID: a.SvID, SmpCnt: a.SmpCnt, ConfRev: a.ConfRev, SmpSynch: uint8(a.SmpSynch), Sample: a.SeqData, GmIdentity: a.GmIdentity}
		if a.DatSet != "" {
			x.DatSet = &a.DatSet
		}
		if !a.RefrTm.IsZero() {
			t := sv.TimestampOf(a.RefrTm, 0)
			x.RefrTm = &t
		}
		if a.SmpRate != 0 {
			r := uint16(a.SmpRate)
			x.SmpRate = &r
		}
		if a.SmpModSet || a.SmpMod != 0 {
			m := sv.SmpMod(a.SmpMod)
			x.SmpMod = &m
		}
		p.ASDUs = append(p.ASDUs, x)
	}
	apdu, err := sv.EncodePDU(p)
	if err != nil {
		return nil
	}
	return ethernet(f.Dst, f.Src, f.VLAN, f.Priority, EtherTypeSV, f.APPID, f.Simulated, apdu)
}

// SeqData packs samples into a sequence of data.
func SeqData(s []Sample) []byte {
	b := make([]byte, 0, 8*len(s))
	for _, x := range s {
		b = binary.BigEndian.AppendUint32(b, uint32(x.Value))
		b = binary.BigEndian.AppendUint32(b, x.Quality)
	}
	return b
}

// decodeGOOSEData reads one allData member. Besides BER it takes the
// fixed-length encoding of 8-1 A.3: integers one octet wider than their
// type (an INT64 in nine octets) and visible strings padded with NULs.
func decodeGOOSEData(e mms.Elem) (mms.Data, error) {
	switch e.Tag {
	case 0xa1, 0xa2: // array, structure
		kids, err := e.Children()
		if err != nil {
			return mms.Data{}, err
		}
		d := mms.Data{Kind: mms.Kind(e.Num), Elems: make([]mms.Data, len(kids))}
		for i, k := range kids {
			if d.Elems[i], err = decodeGOOSEData(k); err != nil {
				return mms.Data{}, err
			}
		}
		return d, nil
	case 0x85:
		if v := e.Val; len(v) == 9 && ((v[0] == 0 && v[1]&0x80 == 0) || (v[0] == 0xff && v[1]&0x80 != 0)) {
			n, err := mms.DecodeInt(v[1:])
			return mms.Integer(n), err
		}
	case 0x8a:
		d, err := mms.DecodeData(e)
		if i := strings.IndexByte(d.Str, 0); i >= 0 {
			d.Str = d.Str[:i]
		}
		return d, err
	}
	return mms.DecodeData(e)
}
