package sv

import (
	"net"
	"reflect"
	"testing"
)

func testCB() MSVCB {
	return MSVCB{Name: "MSVCB01", Ref: "IED1MU/LLN0$MS$MSVCB01", SvEna: true, MsvID: "4000", DatSet: "IED1MU/LLN0$PhsMeas1",
		ConfRev: 1, SmpRate: 80, SmpMod: SmpPerPeriod, NoASDU: 1,
		DstAddress: PhyComAddr{Addr: net.HardwareAddr{1, 0x0C, 0xCD, 4, 0, 1}, Priority: 4, VID: 0, APPID: 0x4000}}
}

// Covers: SIG-IPE-2093
func TestMSVCBValidate(t *testing.T) {
	if err := testCB().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*MSVCB){
		"unicast address":    func(c *MSVCB) { c.DstAddress.Addr = net.HardwareAddr{0, 0x0C, 0xCD, 4, 0, 1} },
		"unconfigured":       func(c *MSVCB) { c.DstAddress.Addr = make(net.HardwareAddr, 6) },
		"priority 8":         func(c *MSVCB) { c.DstAddress.Priority = 8 },
		"VID 4096":           func(c *MSVCB) { c.DstAddress.VID = 4096 },
		"GOOSE APPID":        func(c *MSVCB) { c.DstAddress.APPID = 0x0001 },
		"APPID 0x8000":       func(c *MSVCB) { c.DstAddress.APPID = 0x8000 },
		"SmpMod 3":           func(c *MSVCB) { c.SmpMod = 3 },
		"noASDU 0":           func(c *MSVCB) { c.NoASDU = 0 },
		"SmpRate 0":          func(c *MSVCB) { c.SmpRate = 0 },
		"MsvID empty":        func(c *MSVCB) { c.MsvID = "" },
		"DatSet empty":       func(c *MSVCB) { c.DatSet = "" },
		"ref not in LLN0$MS": func(c *MSVCB) { c.Ref = "IED1MU/LLN0$SV$MSVCB01" },
	} {
		c := testCB()
		mod(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: valid", name)
		}
	}
	// Outside the Annex B range is still configurable (clause 12).
	c := testCB()
	c.DstAddress.Addr = net.HardwareAddr{0x01, 0x00, 0x5E, 0, 0, 1}
	if err := c.Validate(); err != nil {
		t.Errorf("address outside Table B.1: %v", err)
	}
	d := DefaultPhyComAddr()
	if !Unconfigured(d.Addr) || d.Priority != 4 || d.VID != 0 || d.APPID != 0x4000 {
		t.Errorf("default address %+v", d)
	}
	// Table 9 order; SvEna and DstAddress.VID are the writable ones.
	var names []string
	for _, c := range MSVCBComponents {
		names = append(names, c.Name)
		if (c.Access == ReadWrite) != (c.Name == "SvEna") {
			t.Errorf("%s access", c.Name)
		}
	}
	if !reflect.DeepEqual(names, []string{"MsvCBNam", "MsvCBRef", "SvEna", "MsvID", "DatSet", "ConfRev", "SmpRate", "OptFlds", "SmpMod", "DstAddress", "noASDU"}) {
		t.Errorf("components %v", names)
	}
	if PhyComAddrComponents[2].Name != "VID" || PhyComAddrComponents[2].Access != ReadWrite {
		t.Error("PhyComAddr VID")
	}
}

// Covers: SIG-IPE-2093
func TestOptFldsTable20(t *testing.T) {
	for n, o := range []OptFlds{OptRefreshTime, OptSampleSynchronised, OptSampleRate, OptDataSetName, OptSecurity, OptSampleMode, OptSynchSourceIdentity} {
		oct, unused := o.BitString()
		if oct != 0x80>>n || unused != 1 {
			t.Errorf("bit %d: %#x unused %d", n, oct, unused)
		}
		if ParseOptFlds([]byte{oct}) != o {
			t.Errorf("bit %d does not parse back", n)
		}
	}
	all := OptFlds(0x7F)
	if oct, _ := all.BitString(); oct != 0xFE || ParseOptFlds([]byte{0xFF}) != all {
		t.Error("all bits")
	}
}

// Covers: SIG-IPE-2094
func TestSCLAddressTable19(t *testing.T) {
	p := map[string]string{"MAC-Address": "01-0C-CD-04-00-01", "APPID": "4000", "VLAN-PRIORITY": "4", "VLAN-ID": "00A"}
	a, err := ParseSCLAddress(p)
	if err != nil {
		t.Fatal(err)
	}
	if a.Addr.String() != "01:0c:cd:04:00:01" || a.APPID != 0x4000 || a.Priority != 4 || a.VID != 10 {
		t.Errorf("address %+v", a)
	}
	if !reflect.DeepEqual(a.SCL(), p) {
		t.Errorf("SCL() = %v", a.SCL())
	}
	for name, mod := range map[string][2]string{
		"lower-case MAC":  {"MAC-Address", "01-0c-cd-04-00-01"},
		"colons":          {"MAC-Address", "01:0C:CD:04:00:01"},
		"5 groups":        {"MAC-Address", "01-0C-CD-04-00"},
		"APPID 3 chars":   {"APPID", "400"},
		"APPID lower":     {"APPID", "40ab"},
		"priority 8":      {"VLAN-PRIORITY", "8"},
		"priority 2 char": {"VLAN-PRIORITY", "04"},
		"VID 4 chars":     {"VLAN-ID", "0000"},
		"missing VID":     {"VLAN-ID", ""},
	} {
		q := map[string]string{}
		for k, v := range p {
			q[k] = v
		}
		if mod[1] == "" {
			delete(q, mod[0])
		} else {
			q[mod[0]] = mod[1]
		}
		if _, err := ParseSCLAddress(q); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// Covers: SIG-IPE-2095
func TestMulticastAnnexB(t *testing.T) {
	for _, c := range []struct {
		mac   net.HardwareAddr
		in    bool
		mcast bool
	}{
		{net.HardwareAddr{0x01, 0x0C, 0xCD, 0x04, 0x00, 0x00}, true, true},
		{net.HardwareAddr{0x01, 0x0C, 0xCD, 0x04, 0x01, 0xFF}, true, true},
		{net.HardwareAddr{0x01, 0x0C, 0xCD, 0x04, 0x02, 0x00}, false, true},
		{net.HardwareAddr{0x01, 0x0C, 0xCD, 0x01, 0x00, 0x00}, false, true}, // GOOSE range
		{net.HardwareAddr{0x00, 0x0C, 0xCD, 0x04, 0x00, 0x00}, false, false},
	} {
		if InRecommendedRange(c.mac) != c.in || IsMulticast(c.mac) != c.mcast {
			t.Errorf("%v: range %v multicast %v", c.mac, InRecommendedRange(c.mac), IsMulticast(c.mac))
		}
	}
	if !IsBroadcast(net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) || !Unconfigured(net.HardwareAddr{0, 0, 0, 0, 0, 0}) {
		t.Error("broadcast / unconfigured")
	}
}
