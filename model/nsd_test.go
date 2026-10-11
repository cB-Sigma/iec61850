package model

import (
	"reflect"
	"strings"
	"testing"
)

// Covers: SIG-IPE-2063
func TestModelIsTheNSD(t *testing.T) {
	m := mustModel(t)
	if got := m.Versions(); !reflect.DeepEqual(got, []string{"IEC 61850-7-2:2007B6", "IEC 61850-7-3:2007B6", "IEC 61850-7-4:2007B6", "IEC 61850-8-1:2003A4"}) {
		t.Errorf("versions %v", got)
	}
	// every class, enumeration and constructed attribute of the NSD files is in the model
	for _, c := range nsdTablesOf().CDCs {
		n := c.Name
		if c.Variant != "" {
			n += "_" + c.Variant
		}
		mc, ok := m.CDCs[n]
		if !ok {
			t.Errorf("CDC %s missing", n)
			continue
		}
		if len(mc.Attrs) != len(c.Attrs) {
			t.Errorf("%s: %d attributes, NSD has %d", n, len(mc.Attrs), len(c.Attrs))
		}
	}
	for _, e := range nsdTablesOf().Enums {
		me, ok := m.Enums[e.Name]
		if !ok || len(me.Items) != len(e.Items) || me.Source != e.Source {
			t.Errorf("enumeration %s: %+v", e.Name, me)
		}
	}
	for _, c := range nsdTablesOf().CAs {
		if _, ok := m.AttrTypes[c.Name]; !ok {
			t.Errorf("constructed attribute %s missing", c.Name)
		}
	}
	lns := 0
	for _, l := range nsdTablesOf().LNs {
		ml, ok := m.LNs[l.Name]
		if !ok || ml.Abstract != l.Abstract {
			t.Errorf("LN %s: %+v", l.Name, ml)
			continue
		}
		lns++
		// the class's own data objects, and those of every base class
		for b := &l; b != nil; {
			for _, d := range b.DOs {
				if _, ok := ml.DataObject(d.Name); !ok {
					t.Errorf("%s lacks %s of %s", l.Name, d.Name, b.Name)
				}
			}
			var next *nsdLN
			for i := range nsdTablesOf().LNs {
				if nsdTablesOf().LNs[i].Name == b.Base {
					next = &nsdTablesOf().LNs[i]
				}
			}
			b = next
		}
	}
	if lns != 204 || len(nsdTablesOf().Abbreviations) != 1054 {
		t.Errorf("LN classes %d abbreviations %d, want 204 1054", lns, len(nsdTablesOf().Abbreviations))
	}
	// NSD details the OCR tables had wrong (findings F-1150 to F-1156, see PROVENANCE.md)
	for _, c := range []struct{ ln, do, cdc, pres, presDs string }{
		{"CALH", "GrInd", "SPS", "AtLeastOne(1)", "F"},
		{"SIML", "H2O", "MV", "O", "O"},
		{"LLN0", "MltLev", "SPG", "O", "na"},
		{"PTOC", "ClcNxtTmms", "INS", "O", "O"},
		{"LGOS", "Beh", "ENS", "M", "M"},
	} {
		d, ok := m.LNs[c.ln].DataObject(c.do)
		if !ok {
			t.Errorf("%s.%s missing", c.ln, c.do)
			continue
		}
		if d.CDC != c.cdc || d.Pres != c.pres || d.PresDs != c.presDs {
			t.Errorf("%s.%s = %s %s/%s, want %s %s/%s", c.ln, c.do, d.CDC, d.Pres, d.PresDs, c.cdc, c.pres, c.presDs)
		}
	}
	if a, _ := m.FindAttr("DPC", "cdcName"); a == nil {
		t.Error("DPC.cdcName missing")
	}
	if e := m.Enums["ClockSyncKind"]; e == nil {
		t.Error("ClockSyncKind missing")
	} else if l, _ := e.Literal(0); l != "InternalClock" {
		t.Errorf("ClockSyncKind(0) = %q", l)
	}
	if it := m.Enums["CurveCharKind"].Items[3]; it.Name != "ANSI Normal Inverse" || !it.Deprecated {
		t.Errorf("CurveCharKind 3 = %+v", it)
	}
}

// Covers: SIG-IPE-2064
func TestServiceNameSpace81(t *testing.T) {
	m := mustModel(t)
	// the controllable classes are the service CDCs of the 8-1 SNSD
	var ctl []string
	for _, n := range m.CDCNames() {
		if c, _ := m.Control(n); c.Controllable {
			ctl = append(ctl, n)
		}
	}
	if !reflect.DeepEqual(ctl, []string{"SPC", "DPC", "INC", "ENC", "BSC", "ISC", "APC", "BAC"}) {
		t.Errorf("controllable %v", ctl)
	}
	c, _ := m.Control("BSC")
	var oper, cancel []string
	for _, f := range c.OperFields {
		oper = append(oper, f.Name+":"+f.Type+":"+f.Presence)
	}
	for _, f := range c.CancelFields {
		cancel = append(cancel, f.Name)
	}
	if strings.Join(oper, " ") != "ctlVal:StepControlKind:M operTm:Timestamp:MOoperTm origin:Originator:M ctlNum:INT8U:M T:Timestamp:M Test:BOOLEAN:M Check:CheckConditions:M" {
		t.Errorf("Oper %v", oper)
	}
	if strings.Join(cancel, " ") != "ctlVal operTm origin ctlNum T Test" {
		t.Errorf("Cancel %v", cancel)
	}
	// the service data attributes are attributes of the class (SCL DOTypes carry them)
	for _, n := range []string{"SBOw", "Oper", "Cancel"} {
		a, ok := m.FindAttr("DPC", n)
		if !ok || a.FC != "CO" {
			t.Errorf("DPC.%s = %+v", n, a)
		}
	}
	if a, _ := m.FindAttr("SPC", "Oper"); a.Presence != "MOctrl" {
		t.Errorf("SPC.Oper presence %s", a.Presence)
	}
	if _, ok := m.FindAttr("SPS", "Oper"); ok {
		t.Error("SPS has no Oper")
	}
	for _, p := range []string{"MOctrl", "MOsboNormal", "MOsboEnhanced"} {
		if m.Presence[p] == "" {
			t.Errorf("8-1 presence %s has no meaning", p)
		}
	}
}

// Covers: SIG-IPE-2065
func TestFunctionalConstraintServices(t *testing.T) {
	m := mustModel(t)
	if got := m.FCServices["SE"]; !reflect.DeepEqual(got, []string{"GetDataDefinition", "GetDataDirectory", "GetEditSGValue", "SetEditSGValue"}) {
		t.Errorf("SE services %v", got)
	}
	if got := m.FCServices["CO"]; len(got) != 6 || got[0] != "Cancel" {
		t.Errorf("CO services %v", got)
	}
	// 7-2 and 8-1 FCs from the NSD, the control block FCs from text.yaml
	for _, fc := range strings.Fields("ST MX SP SV CF DC SG SE SR OR BL EX CO US MS RP BR LG GO") {
		if m.FCs[fc] == "" {
			t.Errorf("FC %s has no meaning", fc)
		}
	}
	if len(m.FCServices) != 13 {
		t.Errorf("%d FCs with services, want 13", len(m.FCServices))
	}
}

// Covers: SIG-IPE-2066
func TestTextSupplementMatchesNSD(t *testing.T) {
	m := mustModel(t)
	// every abbreviation with a meaning is an NSD abbreviation; the NSD
	// has many more (Light edition, no descriptions)
	names := map[string]bool{}
	for _, a := range m.AbbrevNames {
		names[a] = true
	}
	for a := range m.Abbrev {
		if !names[a] {
			t.Errorf("abbreviation %s is not in the NSD", a)
		}
	}
	if testDescsOK && len(m.Abbrev) != 432 || len(m.AbbrevNames) != 1054 {
		t.Errorf("abbreviations with meaning %d of %d", len(m.Abbrev), len(m.AbbrevNames))
	}
	// Words still spells names out from the supplement
	if w := m.Words("OpDlTmms"); w != "operate delay time in milliseconds" {
		t.Errorf("Words = %q", w)
	}
}

// Covers: SIG-IPE-2074
func TestASDTemplates(t *testing.T) {
	m := mustModel(t)
	rb := m.BAPs["reverse-blocking"].Template
	if rb == nil || rb.Application != "Reverse Blocking" || rb.File != "Reverse Blocking_0_1.asd" {
		t.Fatalf("reverse blocking template %+v", rb)
	}
	var classes []string
	for _, l := range rb.LNs {
		classes = append(classes, l.Class+":"+strings.Join(l.Instances, ","))
	}
	if strings.Join(classes, " ") != "PTOC:PTOC1 TCTR:I01ATCTR,I01BTCTR,I01CTCTR,I01NTCTR PTRC:PTRC1" {
		t.Errorf("template LNs %v", classes)
	}
	ptoc, _ := rb.LN("PTOC")
	if d, ok := ptoc.DO("BlkRef", true); !ok || d.CDC != "ORG" || !reflect.DeepEqual(d.DAs, []string{"setSrcRef"}) {
		t.Errorf("PTOC.BlkRef %+v", d)
	}
	var goose []string
	for _, in := range rb.Inputs {
		if in.Service == "GOOSE" {
			goose = append(goose, in.String())
		}
	}
	if strings.Join(goose, "; ") != "PTOC1 <- PTOC.Str.general (GOOSE); PTOC1 <- PTOC.Str.q (GOOSE); PTRC1 <- PTOC.Op.general (GOOSE); PTRC1 <- PTOC.Op.q (GOOSE)" {
		t.Errorf("GOOSE inputs %v", goose)
	}
	if len(rb.Roles) != 1 || len(rb.Roles[0].Signals["CT"]) != 8 {
		t.Errorf("roles %+v", rb.Roles)
	}
	ld := m.BAPs["line-distance-protection"].Template
	if ld == nil || ld.Application != "Distance Protection" || len(ld.Roles) != 2 {
		t.Fatalf("line distance template %+v", ld)
	}
	pdis, _ := ld.LN("PDIS")
	if len(pdis.Instances) != 3 {
		t.Errorf("PDIS instances %v", pdis.Instances)
	}
	// the TR tables ask for more than the minimal ASD data model (F-1160)
	dep := m.BAPs["line-distance-protection"].TemplateDepartures
	if len(dep) != 21 || !strings.Contains(strings.Join(dep, "\n"), "PSCH.RxBlkn: not in the ASD template's PSCH") {
		t.Errorf("departures %d %v", len(dep), dep)
	}
	if n := len(m.BAPs["reverse-blocking"].TemplateDepartures); n != 0 {
		t.Errorf("reverse blocking departures %v", m.BAPs["reverse-blocking"].TemplateDepartures)
	}
	all, err := Templates()
	if err != nil || len(all) != 2 {
		t.Errorf("templates %d %v", len(all), err)
	}
}

// Covers: SIG-IPE-2075
func TestCheckTemplate(t *testing.T) {
	m := mustModel(t)
	dev := Device{LNs: []LNInstance{
		{Name: "PTOC1", DOs: map[string][]string{
			"Str": {"general", "dirGeneral", "q", "t"}, "Op": {"general", "q", "t"}, "NamPlt": {"lnNs"},
			"Mod": {"stVal", "q", "t", "ctlModel"}, "Blk": {"stVal", "q", "t"}, "OpDlTmms": {"setVal"}, "BlkRef1": {"setSrcRef"}, "BlkRef2": {"setSrcRef"},
		}},
		{Name: "I01ATCTR1", DOs: map[string][]string{"ARtg": {"setMag"}, "HzRtg": {"setMag"}, "Beh": {"stVal", "q", "t"}, "NamPlt": {"lnNs"}, "AmpSv": {"instMag", "q"}}},
		{Name: "PTRC1", DOs: map[string][]string{"Str": nil, "Op": nil, "Tr": nil, "Beh": nil, "NamPlt": nil}},
	}}
	rep, err := m.CheckTemplate("reverse-blocking", dev)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() || len(rep.Subscribed) != 16 {
		t.Fatalf("complete device: %v, %d subscribed", rep.Missing, len(rep.Subscribed))
	}
	delete(dev.LNs[0].DOs, "BlkRef1")
	delete(dev.LNs[0].DOs, "BlkRef2")
	dev.LNs[1].DOs["AmpSv"] = []string{"instMag"}
	dev.LNs = dev.LNs[:2]
	rep, _ = m.CheckTemplate("reverse-blocking", dev)
	var got []string
	for _, i := range rep.Missing {
		got = append(got, i.String())
	}
	if strings.Join(got, "; ") != "missing-do: PTOC1.BlkRef1; missing-da: I01ATCTR1.AmpSv.q; missing-ln: PTRC" {
		t.Errorf("missing %v", got)
	}
	if _, err := m.CheckTemplate("nope", dev); err == nil {
		t.Error("unknown BAP accepted")
	}
}
