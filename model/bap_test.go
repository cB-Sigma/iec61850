package model

import (
	"reflect"
	"strings"
	"testing"
)

// Covers: SIG-IPE-1882
func TestBAPDataMatchesModel(t *testing.T) {
	m := mustModel(t)
	// Load checks every requirement against 7-3/7-4 (b.check); the profiles are there.
	rb, ok := m.BAPs["reverse-blocking"]
	if !ok {
		t.Fatal("reverse-blocking missing")
	}
	if got := rb.Variants(); !reflect.DeepEqual(got, []string{"FA", "FB", "MA", "MB", "TA", "TB"}) {
		t.Errorf("variants %v", got)
	}
	if len(rb.Actors) != 3 || len(rb.Actors[0].Items) != 6 || len(rb.Actors[1].Items) != 4 || len(rb.Actors[2].Items) != 4 {
		t.Errorf("actors %+v", rb.Actors)
	}
	ld, ok := m.BAPs["line-distance-protection"]
	if !ok || len(ld.Variants()) != 10 || len(ld.Actors[0].Items) != 18 {
		t.Fatalf("line distance %+v", ld)
	}
	// a profile naming a data object 7-4 does not have is refused
	bad := &BAP{Name: "x", VariantGroups: []VariantGroup{{Name: "F", Variants: []Variant{{Name: "FA"}}}},
		Actors: []Actor{{Name: "a", Items: []Requirement{
			{LN: "PTOC", DO: "Nope", CDC: "SPS", R: []string{"FA"}},
			{LN: "PTOC", DO: "Str", CDC: "ACT", R: []string{"FA"}},
			{LN: "PTOC", DO: "Op", CDC: "ACT", Attrs: []string{"stVal"}, R: []string{"FB"}},
		}}}}
	errs := bad.check(m)
	if len(errs) != 4 {
		t.Fatalf("errors %v", errs)
	}
}

func reverseBlockingDevice() Device {
	return Device{Name: "infeed", LNs: []LNInstance{
		{Name: "LLN0", DOs: map[string][]string{"Beh": nil, "Mod": nil, "NamPlt": nil}},
		{Name: "PTOC1", DOs: map[string][]string{
			"Beh": nil, "Mod": {"stVal", "q", "t", "ctlModel"},
			"Str": {"general", "dirGeneral", "q", "t"}, "Op": {"general", "q", "t"},
			"Blk": {"stVal", "q", "t"}, "OpDlTmms": {"setVal"},
			"BlkRef1": {"setSrcRef"}, "BlkRef2": {"setSrcRef"},
		}},
	}}
}

// Covers: SIG-IPE-1883
func TestCheckDeviceReverseBlocking(t *testing.T) {
	m := mustModel(t)
	dev := reverseBlockingDevice()
	rep, err := m.CheckDevice("reverse-blocking", "blocked", []string{"FB", "MB", "TB"}, dev)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() || len(rep.Model) != 0 {
		t.Fatalf("complete device: missing %v model %v", rep.Missing, rep.Model)
	}
	// without the blocking inputs and with Op lacking q, the FB variant fails
	delete(dev.LNs[1].DOs, "BlkRef1")
	delete(dev.LNs[1].DOs, "BlkRef2")
	dev.LNs[1].DOs["Op"] = []string{"general", "t"}
	rep, _ = m.CheckDevice("reverse-blocking", "blocked", []string{"FB", "MA", "TA"}, dev)
	var got []string
	for _, i := range rep.Missing {
		got = append(got, i.String())
	}
	if !reflect.DeepEqual(got, []string{"missing-da: PTOC1.Op.q", "missing-do: PTOC1.BlkRef"}) {
		t.Errorf("missing %v", got)
	}
	// FA (wired) needs none of it
	rep, _ = m.CheckDevice("reverse-blocking", "blocked", []string{"FA", "MA", "TA"}, dev)
	if !rep.OK() {
		t.Errorf("FA: %v", rep.Missing)
	}
	// no PTOC at all
	rep, _ = m.CheckDevice("reverse-blocking", "blocking", []string{"FB"}, Device{LNs: []LNInstance{{Name: "LLN0", DOs: map[string][]string{"Beh": nil}}}})
	if len(rep.Missing) != 3 || rep.Missing[0].Kind != "missing-ln" {
		t.Errorf("no PTOC: %v", rep.Missing)
	}
	// client requirements are reported, not failed
	rep, _ = m.CheckDevice("reverse-blocking", "monitoring", []string{"MB", "TB"}, Device{})
	if !rep.OK() || len(rep.ClientRequired) != 4 {
		t.Errorf("monitoring: %+v", rep)
	}
	// variant errors
	if _, err := m.CheckDevice("reverse-blocking", "blocked", []string{"FA", "FB"}, dev); err == nil {
		t.Error("two variants of one group accepted")
	}
	if _, err := m.CheckDevice("reverse-blocking", "blocked", []string{"XX"}, dev); err == nil {
		t.Error("unknown variant accepted")
	}
	if _, err := m.CheckDevice("reverse-blocking", "nobody", nil, dev); err == nil {
		t.Error("unknown actor accepted")
	}
	// departures from 7-4: an unknown data object and a missing mandatory one
	dev.LNs[1].DOs["Foo"] = nil
	delete(dev.LNs[1].DOs, "Str")
	rep, _ = m.CheckDevice("reverse-blocking", "blocked", []string{"FA"}, dev)
	var model []string
	for _, i := range rep.Model {
		model = append(model, i.String())
	}
	if !reflect.DeepEqual(model, []string{"not-in-model: PTOC1.Foo (not a data object of PTOC)", "missing-mandatory: PTOC1.Str"}) {
		t.Errorf("model issues %v", model)
	}
}

// Covers: SIG-IPE-1883
func TestCheckDeviceLineDistance(t *testing.T) {
	m := mustModel(t)
	act := []string{"general", "phsA", "phsB", "phsC", "neut", "q", "t"}
	acd := []string{"general", "dirGeneral", "q", "t"}
	dev := Device{LNs: []LNInstance{
		{Name: "LLN0", DOs: map[string][]string{"Beh": {"stVal", "q", "t"}, "Health": {"stVal", "q", "t"},
			"Mod": {"origin", "ctlNum", "stVal", "q", "t", "ctlModel", "sboTimeout", "sboClass", "operTimeout"}}},
		{Name: "PDIS1", DOs: map[string][]string{"Beh": nil, "Str": acd, "Op": act}},
		{Name: "PDIS2", DOs: map[string][]string{"Beh": nil, "Str": acd, "Op": act}},
		{Name: "PTRC1", DOs: map[string][]string{"Beh": nil, "Str": acd, "Op": act, "Tr": act}},
	}}
	// TPD with test by IEC 61850: PDIS3 and PSCH are missing (Table C.1 marks every PSCH row R
	// under TB, whatever the scheme; see F-787)
	rep, err := m.CheckDevice("line-distance-protection", "distance-protection", []string{"FA", "TPD", "TB", "SB"}, dev)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, i := range rep.Missing {
		got = append(got, i.Requirement)
	}
	want := []string{"PDIS3.Op", "PDIS3.Str", "PSCH.EchoWei", "PSCH.TxPrm", "PSCH.RxPrmn", "PSCH.TxBlk", "PSCH.RxBlkn", "PSCH.Op"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("missing %v, want %v", got, want)
	}
	dev.LNs = append(dev.LNs, LNInstance{Name: "PDIS3", DOs: map[string][]string{"Beh": nil, "Str": acd, "Op": act}},
		LNInstance{Name: "PSCH1", DOs: map[string][]string{"Beh": nil, "Op": nil, "EchoWei": nil, "TxPrm": nil, "RxPrm1": nil,
			"TxBlk": {"general", "q", "t"}, "RxBlk1": {"general", "q", "t"}}})
	rep, _ = m.CheckDevice("line-distance-protection", "distance-protection", []string{"FA", "TPD", "TB", "SB"}, dev)
	if !rep.OK() {
		t.Errorf("complete: %v", rep.Missing)
	}
}

const sclApplication = `<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" xmlns:e="http://www.iec.ch/61850/2019/SCL/6-100">
 <Substation name="S1"><VoltageLevel name="V1"><Bay name="Infeed">
  <Private type="eIEC61850-6-100">
   <e:Application name="RevBlk" type="reverse-blocking" uuid="11111111-2222-3333-4444-555555555555">
    <e:FunctionalVariantGroup name="F">
     <e:FunctionalVariant name="FA" isBaseline="true"/>
     <e:FunctionalVariant name="FB"/>
    </e:FunctionalVariantGroup>
    <e:FunctionalVariantGroup name="M">
     <e:FunctionalVariant name="MA" isBaseline="true"/>
     <e:FunctionalVariant name="MB"><e:FunctionalSubVariant name="MB1"/></e:FunctionalVariant>
    </e:FunctionalVariantGroup>
    <e:AllocationRoleRef allocationRole="/SCL/AllocationRole[@name='Bay']"/>
    <e:FunctionRole name="Blocked" type="blocked">
     <e:FunctionRoleContent roleInst="1">
      <e:FunctionRef function="S1/V1/Infeed/Protection">
       <e:SignalRole name="Pickup"><e:LNodeDataRef data="S1/V1/Infeed/Protection/PTOC1/Str"/></e:SignalRole>
       <e:SignalRole name="BlockIn">
        <e:FunctionalVariantRef functionalVariant="FB"/>
        <e:LNodeInputRef sourceRef="S1/V1/Infeed/Protection/PTOC1/BlkRef1"/>
       </e:SignalRole>
       <e:SignalRole name="OpMon">
        <e:FunctionalVariantRef functionalVariant="MB"/>
        <e:LNodeDataRef data="S1/V1/Infeed/Protection/PTOC1/Op"/>
       </e:SignalRole>
      </e:FunctionRef>
     </e:FunctionRoleContent>
    </e:FunctionRole>
    <e:FunctionRole name="Blocking" type="blocking" cardinality="1..n" max="8">
     <e:FunctionRoleContent roleInst="1">
      <e:FunctionRef function="S1/V1/Feeder1/Protection">
       <e:SignalRole name="Pickup">
        <e:FunctionalVariantRef functionalVariant="FA" update="remove"/>
        <e:LNodeOutputRef controlRef="S1/V1/Feeder1/Protection/PTOC1/Str"/>
       </e:SignalRole>
      </e:FunctionRef>
     </e:FunctionRoleContent>
    </e:FunctionRole>
   </e:Application>
  </Private>
 </Bay></VoltageLevel></Substation>
</SCL>`

// Covers: SIG-IPE-1884
func TestParseApplication(t *testing.T) {
	apps, err := ParseApplications(strings.NewReader(sclApplication))
	if err != nil || len(apps) != 1 {
		t.Fatalf("%v %v", apps, err)
	}
	a := apps[0]
	if a.Name != "RevBlk" || a.Type != "reverse-blocking" || len(a.VariantGroups) != 2 || len(a.FunctionRoles) != 2 || len(a.AllocationRoles) != 1 {
		t.Fatalf("%+v", a)
	}
	if r := a.FunctionRoles[1]; r.Cardinality != "1..n" || r.Max != 8 || a.FunctionRoles[0].Cardinality != "1..1" {
		t.Errorf("cardinality %+v", a.FunctionRoles)
	}
	if a.VariantGroups[1].Variants[1].SubVariants[0].Name != "MB1" {
		t.Errorf("sub variant %+v", a.VariantGroups[1])
	}
	signals := func(chosen ...string) []string {
		s, err := a.Signals(chosen)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, u := range s {
			out = append(out, u.Role+"/"+u.Signal)
		}
		return out
	}
	// baselines FA and MA: the FB input and MB monitoring are out; FA removes the blocking pickup
	if got := signals(); !reflect.DeepEqual(got, []string{"Blocked/Pickup"}) {
		t.Errorf("baseline: %v", got)
	}
	if got := signals("FB", "MB"); !reflect.DeepEqual(got, []string{"Blocked/Pickup", "Blocked/BlockIn", "Blocked/OpMon", "Blocking/Pickup"}) {
		t.Errorf("FB MB: %v", got)
	}
	s, _ := a.Signals([]string{"FB"})
	if s[1].Inputs[0] != "S1/V1/Infeed/Protection/PTOC1/BlkRef1" {
		t.Errorf("input ref %+v", s[1])
	}
	if _, err := a.Signals([]string{"ZZ"}); err == nil {
		t.Error("unknown variant accepted")
	}
	if _, err := ParseApplications(strings.NewReader(`<SCL><Application/></SCL>`)); err == nil {
		t.Error("nameless application accepted")
	}
	if _, err := ParseApplications(strings.NewReader(`<SCL>`)); err == nil {
		t.Error("broken XML accepted")
	}
}
