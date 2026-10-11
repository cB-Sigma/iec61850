package scl

import (
	"strings"
	"testing"

	"github.com/cB-Sigma/iec61850/model"
)

// The gateway IID/CID with controls (SPC and INC per control model, with
// the Oper, SBOw and Cancel structures of the IEC 61850-8-1 service name
// space) and a log control block is valid against the SCL schema and the
// Clause 9 rules, departs from nothing in 7-3/7-4, and the client's SCL
// import finds the controls with their models.
// Covers: SIG-IPE-2900
func TestExportGatewayControlsAndLog(t *testing.T) {
	g := Gateway{IEDName: "SIGMA", FileType: "CID", LDs: []GatewayLD{{Inst: "Feeder", Log: true, SettingGroups: 2,
		GOOSE:    &GatewayGOOSE{AppID: 0x1001, DstMAC: "01-0c-cd-01-00-01", VLANID: 0, VLANPriority: 4, MinTime: 4, MaxTime: 1000, SecurityEnable: "Signature"},
		Settings: []GatewaySetting{{Name: "overcurrent pickup"}, {Name: "delay"}},
		Points:   []GatewayPoint{{Name: "power", Kind: "analog"}, {Name: "breaker", Kind: "binary"}},
		Controls: []GatewayControl{{Name: "breaker", Kind: "binary"}, {Name: "tap", Kind: "integer", CtlModel: "direct-with-normal-security"},
			{Name: "fan", Kind: "binary", CtlModel: "sbo-with-normal-security"}, {Name: "valve", Kind: "binary", CtlModel: "direct-with-enhanced-security"},
			{Name: "timed", Kind: "binary", TimeActivated: true}}}}}
	d, err := ExportGateway(g)
	if err != nil {
		t.Fatal(err)
	}
	if e := errorsOf(Validate(d, Options{})); len(e) > 0 {
		t.Fatalf("exported CID invalid: %v\n%s", e, d.Bytes())
	}
	if m, err := model.Default(); err == nil {
		for _, i := range CheckModel(d, m) {
			t.Errorf("exported templates depart from 7-3/7-4: %v", i)
		}
	}
	ied, _ := d.IED("SIGMA")
	ld, _ := ied.LDevice("Feeder")
	ggio := ld.LN("", "GGIO", "1")
	attrs, err := d.Expand(ggio)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, a := range attrs {
		got[a.DO+"."+a.DA+"/"+a.FC] = a.Value
	}
	for _, want := range []string{"SPCSO1.Oper.ctlVal/CO", "SPCSO1.SBOw.origin.orCat/CO", "SPCSO1.Cancel.Test/CO", "SPCSO1.Oper.Check/CO",
		"ISCSO1.Oper.ctlVal/CO", "SPCSO2.SBO/CO", "SPCSO3.Oper.T/CO", "AnIn1.mag.f/MX", "Ind1.stVal/ST",
		"SPCSO4.Oper.operTm/CO", "SPCSO4.SBOw.operTm/CO", "AnIn1.subMag.f/SV", "Ind1.subVal/SV", "Ind1.blkEna/BL", "AnIn1.subQ/SV"} {
		if _, ok := got[want]; !ok {
			t.Errorf("no %s", want)
		}
	}
	if _, ok := got["SPCSO1.Oper.operTm/CO"]; ok {
		t.Error("a control without time activation has operTm")
	}
	gapc := ld.LN("", "GAPC", "1")
	if gapc == nil || ld.LN0.SettingControl == nil || ld.LN0.SettingControl.NumOfSGs != "2" {
		t.Fatalf("setting groups: %+v", ld.LN0.SettingControl)
	}
	if ld.LN("", "GAPC", "2") == nil {
		t.Error("no GAPC2 for the second setting")
	}
	if sa, _ := d.Expand(gapc); len(sa) < 4 || sa[3].DO != "StrVal" || sa[3].FC != "SG" {
		t.Errorf("settings %+v", sa)
	}
	if _, ok := got["ISCSO1.Cancel.ctlVal/CO"]; ok {
		t.Error("a direct control has Cancel")
	}
	if got["SPCSO1.ctlModel/CF"] != "sbo-with-enhanced-security" || got["ISCSO1.ctlModel/CF"] != "direct-with-normal-security" {
		t.Errorf("ctlModels %q %q", got["SPCSO1.ctlModel/CF"], got["ISCSO1.ctlModel/CF"])
	}
	if len(ld.LN0.LogControls) != 1 || ld.LN0.LogControls[0].LogName != "GeneralLog" || len(ld.LN0.Logs) != 1 {
		t.Errorf("log control %+v logs %+v", ld.LN0.LogControls, ld.LN0.Logs)
	}
	pubs, err := d.Publications("SIGMA", false)
	if err != nil || len(pubs) != 1 || len(pubs[0].Members) != 4 {
		t.Fatalf("GOOSE publications %+v %v", pubs, err)
	}
	if !strings.Contains(string(d.Bytes()), `fileType="CID"`) {
		t.Error("not a CID")
	}
	if _, err := ExportGateway(Gateway{IEDName: "X", LDs: []GatewayLD{{Inst: "A", Controls: []GatewayControl{{Name: "c", Kind: "binary", CtlModel: "status-only"}}}}}); err == nil {
		t.Error("a status-only control accepted")
	}
}
