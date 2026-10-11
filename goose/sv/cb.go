package sv

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// OptFlds is the MSVCB OptFlds bit string (Table 9); bit n of Table 20
// is the mask 1<<n here.
type OptFlds uint8

// OptFlds bits (Table 20).
const (
	OptRefreshTime OptFlds = 1 << iota
	// OptSampleSynchronised is ignored; it stays for the 2004 edition.
	OptSampleSynchronised
	OptSampleRate
	OptDataSetName
	OptSecurity
	OptSampleMode
	OptSynchSourceIdentity

	// OptFldsBits is the number of bits of the MMS bit string.
	OptFldsBits = 7
)

// BitString is the MMS bit string form: bit 0 is the most significant
// bit of the first octet, and one trailing bit is unused.
func (o OptFlds) BitString() (octet byte, unused int) {
	for n := 0; n < OptFldsBits; n++ {
		if o&(1<<n) != 0 {
			octet |= 0x80 >> n
		}
	}
	return octet, 8 - OptFldsBits
}

// ParseOptFlds reads the MMS bit string form (bits past 6 are ignored).
func ParseOptFlds(b []byte) OptFlds {
	var o OptFlds
	for n := 0; n < OptFldsBits && n/8 < len(b); n++ {
		if b[n/8]&(0x80>>(n%8)) != 0 {
			o |= 1 << n
		}
	}
	return o
}

// PhyComAddr is the MSVCB DstAddress (Table 10).
type PhyComAddr struct {
	Addr     net.HardwareAddr // 6 octets, multicast
	Priority uint8            // 0..7
	VID      uint16           // 0..4095
	APPID    uint16           // 5.3.3.4.2
}

// DefaultPhyComAddr is the address of a control block with nothing
// configured: address 00-00-00-00-00-00 (Annex B), priority 4 and VID 0
// (Table 7), APPID 0x4000 (5.3.3.4.2).
func DefaultPhyComAddr() PhyComAddr {
	return PhyComAddr{Addr: make(net.HardwareAddr, 6), Priority: DefaultPriority, VID: DefaultVID, APPID: APPIDDefault}
}

// Validate checks the ranges of Table 10.
func (a PhyComAddr) Validate() error {
	if len(a.Addr) != 6 {
		return errors.New("sv: DstAddress Addr must be 6 octets")
	}
	if Unconfigured(a.Addr) {
		return errors.New("sv: DstAddress Addr is 00-00-00-00-00-00, not configured (Annex B)")
	}
	if !IsMulticast(a.Addr) {
		return errors.New("sv: DstAddress Addr must have the multicast bit set (Table 10)")
	}
	if a.Priority > 7 {
		return errors.New("sv: PRIORITY must be 0..7 (Table 10)")
	}
	if a.VID > 4095 {
		return errors.New("sv: VID must be 0..4095 (Table 10)")
	}
	if a.APPID < APPIDMin || a.APPID > APPIDMax {
		return fmt.Errorf("sv: APPID %#04x outside 0x4000-0x7FFF (5.3.3.4.2)", a.APPID)
	}
	return nil
}

// Access is the r/w column of Tables 9 and 10.
type Access int

// Access values.
const (
	Read Access = iota
	ReadWrite
)

// Component is one MSVCB component (Table 9): all have the functional
// constraint MS (8.2.1).
type Component struct {
	Name   string
	Type   string
	Access Access
}

// MSVCBComponents lists Table 9 in order (OptFlds members in Table 20
// order, DstAddress members as in Table 10).
var MSVCBComponents = []Component{
	{"MsvCBNam", "Identifier", Read},
	{"MsvCBRef", "Visible-string", Read},
	{"SvEna", "Boolean", ReadWrite},
	{"MsvID", "Visible-string", Read},
	{"DatSet", "Visible-string", Read},
	{"ConfRev", "Unsigned integer", Read},
	{"SmpRate", "Unsigned integer", Read},
	{"OptFlds", "Bitstring", Read},
	{"SmpMod", "Enumerated", Read},
	{"DstAddress", "PhyComAddr", Read}, // no r/w given; Addr, PRIORITY and APPID read, VID r/w (F-1085)
	{"noASDU", "Unsigned integer", Read},
}

// PhyComAddrComponents lists Table 10.
var PhyComAddrComponents = []Component{
	{"Addr", "OCTET-STRING", Read},
	{"PRIORITY", "Unsigned8", Read},
	{"VID", "Unsigned16", ReadWrite},
	{"APPID", "Unsigned16", Read},
}

// MSVCB is the multicast sampled value control block (8.2.1, Table 9).
// The unicast control block is deprecated (8.3, C.2 use case 35a) and has
// no mapping.
type MSVCB struct {
	Name       string // MsvCBNam, in LLN0$MS
	Ref        string // MsvCBRef, <domain>/LLN0$MS$<name>
	SvEna      bool
	MsvID      string
	DatSet     string
	ConfRev    uint32
	SmpRate    uint16
	OptFlds    OptFlds
	SmpMod     SmpMod
	DstAddress PhyComAddr
	NoASDU     uint16
}

// RecommendedMsvID is the identification Tables 9 and 14 recommend: the
// APPID in hexadecimal, read as four hexadecimal characters (F-1077).
func RecommendedMsvID(appid uint16) string { return fmt.Sprintf("%04X", appid) }

// Validate checks the control block against Tables 9, 10 and 14.
func (c MSVCB) Validate() error {
	if _, err := visible([]byte(c.MsvID), "MsvID", MaxVisString, false); err != nil {
		return fmt.Errorf("sv: %w", err)
	}
	if _, err := visible([]byte(c.DatSet), "DatSet", MaxVisString, false); err != nil {
		return fmt.Errorf("sv: %w", err)
	}
	if c.Ref != "" && !strings.Contains(c.Ref, "/LLN0$MS$") {
		return errors.New("sv: MsvCBRef must name a control block in LLN0 with constraint MS (Table 9)")
	}
	if c.SmpRate == 0 {
		return errors.New("sv: SmpRate must be above 0")
	}
	if c.SmpMod > SecPerSample {
		return fmt.Errorf("sv: SmpMod %d is not 0, 1 or 2 (Table 9)", c.SmpMod)
	}
	if c.NoASDU == 0 {
		return errors.New("sv: noASDU must be 1..65535 (Table 14)")
	}
	return c.DstAddress.Validate()
}

// ---- SCL address (clause 12, Table 19) ------------------------------------

// P-type names of Table 19.
const (
	PMACAddress   = "MAC-Address"
	PAPPID        = "APPID"
	PVLANPriority = "VLAN-PRIORITY"
	PVLANID       = "VLAN-ID"
)

func upperHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < n; i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// ParseSCLAddress reads the P elements of an SMV address (Table 19); all
// four are mandatory and their characters are restricted as listed.
func ParseSCLAddress(p map[string]string) (PhyComAddr, error) {
	var a PhyComAddr
	mac, ok := p[PMACAddress]
	parts := strings.Split(mac, "-")
	if !ok || len(parts) != 6 {
		return a, errors.New("sv: MAC-Address must be 6 groups of 2 characters separated by hyphens")
	}
	a.Addr = make(net.HardwareAddr, 6)
	for i, g := range parts {
		if !upperHex(g, 2) {
			return a, errors.New("sv: MAC-Address characters must be 0-9 and A-F")
		}
		v, _ := strconv.ParseUint(g, 16, 8)
		a.Addr[i] = byte(v)
	}
	s, ok := p[PAPPID]
	if !ok || !upperHex(s, 4) {
		return a, errors.New("sv: APPID must be 4 characters 0-9, A-F")
	}
	v, _ := strconv.ParseUint(s, 16, 16)
	a.APPID = uint16(v)
	s, ok = p[PVLANPriority]
	if !ok || len(s) != 1 || s[0] < '0' || s[0] > '7' {
		return a, errors.New("sv: VLAN-PRIORITY must be one character 0-7")
	}
	a.Priority = s[0] - '0'
	s, ok = p[PVLANID]
	if !ok || !upperHex(s, 3) {
		return a, errors.New("sv: VLAN-ID must be 3 characters 0-9, A-F")
	}
	v, _ = strconv.ParseUint(s, 16, 16)
	a.VID = uint16(v)
	return a, nil
}

// SCL gives the P elements of Table 19 for the address.
func (a PhyComAddr) SCL() map[string]string {
	g := make([]string, len(a.Addr))
	for i, c := range a.Addr {
		g[i] = fmt.Sprintf("%02X", c)
	}
	return map[string]string{PMACAddress: strings.Join(g, "-"), PAPPID: fmt.Sprintf("%04X", a.APPID),
		PVLANPriority: strconv.Itoa(int(a.Priority)), PVLANID: fmt.Sprintf("%03X", a.VID)}
}

// ---- multicast addresses (Annex B, informative) ---------------------------

// Recommended multicast range for sampled values (Table B.1).
var (
	RecommendedFirst = net.HardwareAddr{0x01, 0x0C, 0xCD, 0x04, 0x00, 0x00}
	RecommendedLast  = net.HardwareAddr{0x01, 0x0C, 0xCD, 0x04, 0x01, 0xFF}
)

// IsMulticast: the first transmitted bit (the least significant bit of
// the first octet) is 1.
func IsMulticast(a net.HardwareAddr) bool { return len(a) == 6 && a[0]&1 == 1 }

// IsBroadcast is FF-FF-FF-FF-FF-FF.
func IsBroadcast(a net.HardwareAddr) bool {
	return bytes.Equal(a, net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
}

// Unconfigured is 00-00-00-00-00-00, the address not yet configured.
func Unconfigured(a net.HardwareAddr) bool { return bytes.Equal(a, make(net.HardwareAddr, 6)) }

// InRecommendedRange reports whether a lies in the Table B.1 range.
// Addresses outside it stay configurable (clause 12).
func InRecommendedRange(a net.HardwareAddr) bool {
	return len(a) == 6 && bytes.Compare(a, RecommendedFirst) >= 0 && bytes.Compare(a, RecommendedLast) <= 0
}
