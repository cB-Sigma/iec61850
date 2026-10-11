package scl

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850/model"
)

// Covers: SIG-IPE-2054, SIG-IPE-2055, SIG-IPE-2062
func TestPublications(t *testing.T) {
	d, _ := load(t, "clause9.scd")
	gs, err := d.Publications("E1Q1SB1", false)
	if err != nil || len(gs) != 1 {
		t.Fatalf("%v %v", gs, err)
	}
	g := gs[0]
	if g.CBRef != "E1Q1SB1C1/LLN0$GO$ItlPositions" || g.ID != "Itl" || g.DataSet != "E1Q1SB1C1/LLN0$Positions" || g.ConfRev != 1 {
		t.Errorf("GOOSE block %+v", g)
	}
	if g.APPID != 0x3000 || g.DstMAC != "01-0C-CD-01-00-01" || g.Priority == nil || *g.Priority != 4 || g.VLANID != nil {
		t.Errorf("GOOSE address %+v", g)
	}
	if !g.Offered.Signature || g.Offered.Encryption || g.SecurityEnable != "None" {
		t.Errorf("security %+v", g)
	}
	var names []string
	for _, m := range g.Members {
		names = append(names, m.Name+"/"+m.FC+"/"+m.BType)
	}
	if !slices.Equal(names, []string{"CSWI1.Pos/ST/Struct", "CSWI2.Pos/ST/Struct"}) {
		t.Errorf("members %v", names)
	}
	// 9.4.7: MinTime 4 and MaxTime 1000 (milliseconds).
	sy, _ := d.Publications("D1Q1SB4", false)
	if len(sy) != 1 || sy[0].MinTime != 4*time.Millisecond || sy[0].MaxTime != time.Second || sy[0].APPID != 0x3001 {
		t.Errorf("SyckResult %+v", sy)
	}
	if m := sy[0].Members; len(m) != 2 || m[0].BType != "Dbpos" || m[1].BType != "Quality" {
		t.Errorf("SyckResult members %+v", m)
	}
	svs, _ := d.Publications("E1Q1SB1", true)
	if len(svs) != 1 {
		t.Fatal(svs)
	}
	sv := svs[0]
	if sv.CBRef != "E1Q1SB1C1/LLN0$MS$Volt" || sv.ID != "11" || sv.SmpRate != 4800 || sv.NofASDU != 5 || sv.APPID != 0x4000 || sv.VLANID == nil || *sv.VLANID != 0x123 || !sv.Multicast {
		t.Errorf("SV %+v", sv)
	}
	// Subscriptions: by the ExtRef (D1Q1SB4 takes ItlPositions) and by
	// the IEDName list (E1Q1SB1 takes SyckResult).
	sub, _ := d.Subscriptions("D1Q1SB4", false)
	if len(sub) != 1 || sub[0].Name != "ItlPositions" {
		t.Errorf("D1Q1SB4 subscribes to %+v", sub)
	}
	sub, _ = d.Subscriptions("E1Q1SB1", false)
	if len(sub) != 1 || sub[0].Name != "SyckResult" {
		t.Errorf("E1Q1SB1 subscribes to %+v", sub)
	}
	svsub, _ := d.Subscriptions("D1Q1SB4", true)
	if len(svsub) != 1 || svsub[0].Name != "Volt" {
		t.Errorf("SV subscriptions %+v", svsub)
	}
	ied, _ := d.IED("E1Q1SB1")
	if _, ok := ied.SubscriberSecurity(false); ok {
		t.Error("no ClientServices McSecurity was declared")
	}
}

// Covers: SIG-IPE-2049
func TestCheckModel(t *testing.T) {
	needNSD(t)
	m, err := model.Default()
	if err != nil {
		t.Fatal(err)
	}
	d, _ := load(t, "clause9.scd")
	is := CheckModel(d, m)
	if !is.Has("MMXU.Volts is not a data object") {
		t.Errorf("vendor data object not reported: %v", is)
	}
	for _, i := range is {
		if i.Severity != Warning {
			t.Errorf("model departures must be warnings: %v", i)
		}
		if strings.Contains(i.Msg, "CSWI.Pos") {
			t.Errorf("standard object flagged: %v", i)
		}
	}
	bad := strings.Replace(string(mustRead(t, "clause9.scd")), `<DO name="Pos" type="DPC_T"/>`, `<DO name="Pos" type="ACT_T"/>`, 1)
	d, _ = Parse([]byte(bad))
	if !CheckModel(d, m).Has("CSWI.Pos uses DOType ACT_T of class ACT; IEC 61850-7-4 gives DPC") {
		t.Error("CDC mismatch not reported")
	}
}

const bapIED = `<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" xmlns:e="http://www.iec.ch/61850/2019/SCL/6-100" version="2007" revision="C" release="5">
	<Header id="bap" uuid="3f2b8f0e-2c1d-4a5b-9e7f-1a2b3c4d5e6f"/>
	<Substation name="S1"><VoltageLevel name="V1"><Bay name="Infeed">
		<Private type="eIEC61850-6-100">
			<e:Application name="RevBlk" type="reverse-blocking">
				<e:FunctionalVariantGroup name="F"><e:FunctionalVariant name="FA" isBaseline="true"/><e:FunctionalVariant name="FB"/></e:FunctionalVariantGroup>
				<e:FunctionRole name="Blocked" type="blocked">
					<e:FunctionRoleContent roleInst="1"><e:FunctionRef function="S1/V1/Infeed/Protection">
						<e:SignalRole name="Pickup"><e:LNodeDataRef data="S1/V1/Infeed/Protection/PTOC1/Str"/></e:SignalRole>
					</e:FunctionRef></e:FunctionRoleContent>
				</e:FunctionRole>
			</e:Application>
		</Private>
	</Bay></VoltageLevel></Substation>
	<IED name="Infeed">
		<AccessPoint name="S1"><Server><Authentication/>
			<LDevice inst="Prot">
				<LN0 lnClass="LLN0" inst="" lnType="L0"/>
				<LN lnClass="PTOC" inst="1" lnType="PTOC_T"/>
			</LDevice>
		</Server></AccessPoint>
	</IED>
	<DataTypeTemplates>
		<LNodeType id="L0" lnClass="LLN0"><DO name="Beh" type="ENS"/></LNodeType>
		<LNodeType id="PTOC_T" lnClass="PTOC"><DO name="Beh" type="ENS"/><DO name="Mod" type="ENC"/><DO name="Str" type="ACD"/><DO name="Op" type="ACT"/><DO name="OpDlTmms" type="ING"/><DO name="BlkRef1" type="ORG"/></LNodeType>
		<DOType id="ENS" cdc="ENS"><DA name="stVal" fc="ST" bType="INT32"/><DA name="q" fc="ST" bType="Quality"/><DA name="t" fc="ST" bType="Timestamp"/></DOType>
		<DOType id="ENC" cdc="ENC"><DA name="stVal" fc="ST" bType="INT32"/><DA name="q" fc="ST" bType="Quality"/><DA name="t" fc="ST" bType="Timestamp"/></DOType>
		<DOType id="ACD" cdc="ACD"><DA name="general" fc="ST" bType="BOOLEAN"/><DA name="dirGeneral" fc="ST" bType="INT32"/><DA name="q" fc="ST" bType="Quality"/><DA name="t" fc="ST" bType="Timestamp"/></DOType>
		<DOType id="ACT" cdc="ACT"><DA name="general" fc="ST" bType="BOOLEAN"/><DA name="q" fc="ST" bType="Quality"/><DA name="t" fc="ST" bType="Timestamp"/></DOType>
		<DOType id="ING" cdc="ING"><DA name="setVal" fc="SP" bType="INT32"/></DOType>
		<DOType id="ORG" cdc="ORG"><DA name="setSrcRef" fc="SP" bType="ObjRef"/></DOType>
	</DataTypeTemplates>
</SCL>`

// Covers: SIG-IPE-2058
func TestBAP(t *testing.T) {
	needNSD(t)
	m, err := model.Default()
	if err != nil {
		t.Fatal(err)
	}
	d, err := Parse([]byte(bapIED))
	if err != nil {
		t.Fatal(err)
	}
	if e := errorsOf(Validate(d, Options{})); len(e) > 0 {
		t.Errorf("BAP vector invalid: %v", e)
	}
	apps, err := Applications(d)
	if err != nil || len(apps) != 1 || apps[0].Type != "reverse-blocking" {
		t.Fatalf("applications %v %v", apps, err)
	}
	rep, err := CheckBAP(d, m, "Infeed", "reverse-blocking", "blocked", []string{"FB", "MA", "TA"})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Errorf("complete IED: %v", rep.Missing)
	}
	d2, _ := Parse([]byte(strings.Replace(bapIED, `<DO name="Str" type="ACD"/>`, ``, 1)))
	rep, _ = CheckBAP(d2, m, "Infeed", "reverse-blocking", "blocked", []string{"FB", "MA", "TA"})
	if rep.OK() {
		t.Error("the missing Str was not reported")
	}
}

// Covers: SIG-IPE-2057
func TestExportGateway(t *testing.T) {
	g := Gateway{IEDName: "SIGMA1", UUID: "6dacf413-cb9e-4ce8-8a45-7c6325b1afab",
		Address: []P{{Type: "IP", Value: "10.0.0.50"}, {Type: "OSI-TSEL", Value: "0001"}},
		LDs: []GatewayLD{{Inst: "Meter1", Points: []GatewayPoint{{Name: "energy", Kind: "analog"}, {Name: "door", Kind: "binary", Desc: "cabinet door"}, {Name: "count", Kind: "integer"}}},
			{Inst: "Pump", Points: []GatewayPoint{{Name: "flow", Kind: "analog"}, {Name: "level", Kind: "analog"}}}}}
	d, err := ExportGateway(g)
	if err != nil {
		t.Fatal(err)
	}
	if e := errorsOf(Validate(d, Options{})); len(e) > 0 {
		t.Fatalf("exported IID invalid: %v\n%s", e, d.Bytes())
	}
	m, _ := model.Default()
	for _, i := range CheckModel(d, m) {
		t.Errorf("exported templates depart from 7-3/7-4: %v", i)
	}
	back, err := Parse(d.Bytes())
	if err != nil || !Equal(back.Tree, d.Tree) {
		t.Fatalf("exported file does not read back: %v", err)
	}
	ied, _ := back.IED("SIGMA1")
	ld, _ := ied.LDevice("Pump")
	if ld.Name("SIGMA1") != "SIGMA1Pump" || len(ld.LN0.DataSets[0].FCDAs) != 2 {
		t.Errorf("Pump LD %+v", ld)
	}
	if ca, _ := back.ConnectedAP("SIGMA1", "S1"); ca == nil {
		t.Error("no ConnectedAP")
	} else if ip, _ := ca.Address.Get("IP"); ip != "10.0.0.50" {
		t.Errorf("ip %s", ip)
	}
	if _, err := ExportGateway(Gateway{IEDName: "None"}); err == nil {
		t.Error("IED name None accepted")
	}
	if _, err := ExportGateway(Gateway{IEDName: "X", LDs: []GatewayLD{{Inst: "A", Points: []GatewayPoint{{Name: "s", Kind: "text"}}}}}); err == nil {
		t.Error("unsupported kind accepted")
	}
}
