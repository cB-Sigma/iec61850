package scl

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"
)

func load(t *testing.T, name string) (*Document, []byte) {
	t.Helper()
	raw, err := os.ReadFile(testFile(t, name))
	if err != nil {
		t.Fatal(err)
	}
	d, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return d, raw
}

func errorsOf(is Issues) []string {
	var out []string
	for _, i := range is.Errors() {
		out = append(out, i.String())
	}
	return out
}

// Covers: SIG-IPE-2030
func TestLosslessRoundTrip(t *testing.T) {
	// Private content, foreign elements and attributes survive and are
	// not in the typed model (this module's own test system).
	b, raw := load(t, "bay.scd")
	out := b.Bytes()
	if !bytes.Equal(out, raw) {
		t.Error("bay.scd: not byte-identical")
	}
	for _, want := range []string{`<tst:note>kept on export</tst:note>`, `<Private type="tst-tool">opaque <tst:y b="2"/></Private>`, `<!-- Test system of this module`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("bay.scd output lacks %s", want)
		}
	}
	// The files around the standard's examples.
	for _, f := range []string{"ssd_9_2_8.ssd", "clause9.scd", "coordinates_annex_c.scd"} {
		d, raw := load(t, f)
		out := d.Bytes()
		again, err := ParseTree(out)
		if err != nil {
			t.Fatalf("%s: re-read: %v", f, err)
		}
		if !Equal(d.Tree, again) {
			t.Errorf("%s: the written tree differs from the read one", f)
		}
		// Files that use plain attribute layout come back byte for byte.
		if f != "coordinates_annex_c.scd" && !bytes.Equal(out, raw) {
			t.Errorf("%s: not byte-identical", f)
		}
	}
	// Private content, foreign elements and attributes survive and are
	// not in the typed model.
	d, _ := load(t, "clause9.scd")
	c9 := string(d.Bytes())
	for _, want := range []string{`<eSig:note>kept on export</eSig:note>`, `<Private type="eSig-vendor">tool data <eSig:x a="1"/></Private>`, `<!-- Our test system`} {
		if !strings.Contains(c9, want) {
			t.Errorf("output lacks %s", want)
		}
	}
	c, _ := load(t, "coordinates_annex_c.scd")
	if !strings.Contains(string(c.Bytes()), `sxy:dir="horizontal"`) {
		t.Error("the Annex C coordinate attributes were not kept")
	}
	if c.SCL.Substations[0].Name != "Baden220_132" {
		t.Errorf("substation = %q", c.SCL.Substations[0].Name)
	}
}

// Covers: SIG-IPE-2031, SIG-IPE-2037
func TestSSDExample(t *testing.T) {
	d, _ := load(t, "ssd_9_2_8.ssd")
	if v := d.SCL.SchemaVersion(); v != Supported {
		t.Errorf("version = %v", v)
	}
	is := Validate(d, Options{FileType: "SSD"})
	if e := errorsOf(is); len(e) > 0 {
		t.Errorf("the 9.2.8 example has errors: %v", e)
	}
	s := d.SCL.Substations[0]
	var vls []string
	for _, c := range s.Children {
		if c.XMLName.Local == "VoltageLevel" {
			vls = append(vls, c.Name+"/"+c.NomFreq)
		}
	}
	if !slices.Equal(vls, []string{"D1/50", "E1/"}) {
		t.Errorf("voltage levels = %v", vls)
	}
	// A terminal pointing at an unknown node, a duplicate name and a
	// duplicate LNode link are reported.
	bad := strings.Replace(string(mustRead(t, "ssd_9_2_8.ssd")), `connectivityNode="Baden220_132/E1/W1/B1"`, `connectivityNode="Baden220_132/E1/W1/B9"`, 1)
	bad = strings.Replace(bad, `name="QB1"`, `name="QA1"`, 1)
	bad = strings.Replace(bad, `<LNode lnInst="2" lnClass="CILO"`, `<LNode lnInst="2" lnClass="CSWI"`, 1)
	db, err := Parse([]byte(bad))
	if err != nil {
		t.Fatal(err)
	}
	is = Validate(db, Options{FileType: "SSD"})
	for _, want := range []string{"B9\" which is not defined", "name \"QA1\" is used twice", "two LNode elements"} {
		if !is.Has(want) {
			t.Errorf("missing issue %q in %v", want, errorsOf(is))
		}
	}
}

func mustRead(t *testing.T, f string) []byte {
	t.Helper()
	b, err := os.ReadFile(testFile(t, f))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Covers: SIG-IPE-2032, SIG-IPE-2033, SIG-IPE-2040, SIG-IPE-2048
func TestClause9Example(t *testing.T) {
	d, _ := load(t, "clause9.scd")
	is := Validate(d, Options{FileType: "SCD"})
	// The one defect is the standard's own data set example (9.3.7):
	// doName " TmASt " carries blanks (F-1036).
	var errs []string
	for _, i := range is.Errors() {
		errs = append(errs, i.Msg)
	}
	if len(errs) == 0 || !slices.ContainsFunc(errs, func(s string) bool { return strings.Contains(s, `doName=" TmASt "`) }) {
		t.Errorf("the blank doName of the 9.3.7 example was not reported: %v", errs)
	}
	for _, e := range errs {
		if !strings.Contains(e, "TmASt") {
			t.Errorf("unexpected error %s", e)
		}
	}
	// Warnings: the example ClientLN at a pure client access point uses
	// ldInst "none" (F-1037) and the GSEControl subscriber is outside.
	if !is.Has("pure client access point") {
		t.Errorf("ClientLN ldInst none not flagged: %v", is)
	}
	ied, err := d.IED("E1Q1SB1")
	if err != nil {
		t.Fatal(err)
	}
	ld, _ := ied.LDevice("C1")
	if ld.Name(ied.Name) != "E1Q1SB1C1" {
		t.Errorf("LD name = %s", ld.Name(ied.Name))
	}
	rc := ld.LN0.ReportControls[0]
	if !slices.Equal(rc.Instances(), []string{"PosReport01", "PosReport02", "PosReport03", "PosReport04", "PosReport05"}) || rc.IsBuffered() {
		t.Errorf("9.3.8 instances = %v", rc.Instances())
	}
	if !slices.Equal(rc.TrgOps.List(), []string{"dchg", "qchg", "gi"}) || !slices.Equal(rc.OptFields.List(), []string{"bufOvfl"}) {
		t.Errorf("trgops %v optfields %v", rc.TrgOps.List(), rc.OptFields.List())
	}
	if lc := ld.LN0.LogControls[0]; lc.LogName != "C1" || !slices.Equal(lc.TrgOps.List(), []string{"dchg", "qchg", "gi"}) {
		t.Errorf("9.3.9 log control = %+v", lc)
	}
	a, gse := d.GSEAddress("E1Q1SB1", "C1", "ItlPositions", false)
	if a == nil || gse.APName != "S1" {
		t.Fatal("GSE address of ItlPositions not found")
	}
	if mac, _ := a.Address.Get("MAC-Address"); mac != "01-0C-CD-01-00-01" {
		t.Errorf("mac = %s", mac)
	}
	// Expansion applies DOI values over template values.
	var mmxu *LN
	for _, ln := range ld.AllLNs() {
		if ln.Name() == "MMXU1" {
			mmxu = ln
		}
	}
	attrs, err := d.Expand(mmxu)
	if err != nil {
		t.Fatal(err)
	}
	vals := map[string]string{}
	for _, at := range attrs {
		vals[at.DO+"."+at.DA+"["+at.FC+"]"] = at.Value
	}
	if vals["Volts.sVC.scaleFactor[CF]"] != "200" || vals["Volts.units.SIUnit[CF]"] != "V" {
		t.Errorf("expanded values = %v", vals)
	}
	if _, ok := vals["PhV.phsA.cVal.mag.f[MX]"]; !ok {
		t.Errorf("sub data object attributes missing: %v", vals)
	}
}

// Covers: SIG-IPE-2034
func TestMustUnderstand(t *testing.T) {
	// 8.2.1: an unknown element marked mustUnderstand makes the parent
	// unusable; one without the mark is ignored with a warning.
	doc := func(extra string) Issues {
		src := strings.Replace(string(mustRead(t, "clause9.scd")), `<IEDName apRef="S1">E1Q1SB1</IEDName>`, `<IEDName apRef="S1">E1Q1SB1</IEDName>`+extra, 1)
		d, err := Parse([]byte(src))
		if err != nil {
			t.Fatal(err)
		}
		return Validate(d, Options{})
	}
	is := doc(`<Future mustUnderstand="true">x</Future>`)
	if !is.Has("marked mustUnderstand is not known: GSEControl cannot be used") {
		t.Errorf("mustUnderstand not enforced: %v", errorsOf(is))
	}
	is = doc(`<Future>x</Future>`)
	if !is.Has("element Future is not known in GSEControl and is ignored") {
		t.Errorf("may-ignore warning missing")
	}
	// The 8.2.1 example itself: Protocol R-GOOSE with mustUnderstand is
	// known to us and accepted.
	is = doc(`<Protocol mustUnderstand="true">R-GOOSE</Protocol>`)
	if is.Has("Protocol") {
		t.Errorf("Protocol R-GOOSE refused: %v", is)
	}
}

// Covers: SIG-IPE-2035
func TestVersions(t *testing.T) {
	src := string(mustRead(t, "clause9.scd"))
	newer := strings.Replace(src, `revision="C" release="5">`, `revision="D" release="1">`, 1)
	d, _ := Parse([]byte(newer))
	if is := Validate(d, Options{}); !is.Has("newer than the supported 2007C5") || len(is.Errors()) != 2 {
		t.Errorf("newer version: %v", errorsOf(is))
	}
	if is := Validate(d, Options{RefuseNewer: true}); len(is.Errors()) != 3 {
		t.Errorf("RefuseNewer did not refuse: %v", errorsOf(is))
	}
	noVer := strings.Replace(src, `version="2007" revision="C" release="5"`, ``, 1)
	d, _ = Parse([]byte(noVer))
	if d.SCL.SchemaVersion() != (Version{2003, "A", 1}) {
		t.Errorf("default version = %v", d.SCL.SchemaVersion())
	}
}

// Covers: SIG-IPE-2036
func TestNamespaceRules(t *testing.T) {
	src := strings.Replace(string(mustRead(t, "clause9.scd")), `<Private type="eSig-vendor">`, `<Private>`, 1)
	d, _ := Parse([]byte(src))
	if !Validate(d, Options{}).Has("Private needs a type") {
		t.Error("Private without type accepted")
	}
	src = strings.Replace(string(mustRead(t, "clause9.scd")), `<ClientServices goose="true" bufReport="true"/>
		</Services>`, `<ClientServices goose="true" bufReport="true"/>
		</Services><eSig:late/>`, 1)
	d, _ = Parse([]byte(src))
	if !Validate(d, Options{}).Has("follows SCL elements") {
		t.Error("a foreign element after SCL elements was accepted")
	}
	noNS := `<SCL version="2007" revision="C" release="5"><Header id="x"/><Communication><SubNetwork name="a"><ConnectedAP iedName="X" apName="Y"/></SubNetwork></Communication></SCL>`
	d, err := Parse([]byte(noNS))
	if err != nil {
		t.Fatal(err)
	}
	if !Validate(d, Options{}).Has("namespace") {
		t.Error("missing SCL namespace not reported")
	}
	if _, err := Parse([]byte(`<Foo xmlns="` + NS + `"/>`)); err == nil {
		t.Error("a non-SCL root was accepted")
	}
	if _, err := Parse([]byte(`<SCL xmlns="` + NS + `"><Header`)); err == nil {
		t.Error("broken XML was accepted")
	}
}

// Covers: SIG-IPE-2038, SIG-IPE-2039, SIG-IPE-2041, SIG-IPE-2042, SIG-IPE-2043, SIG-IPE-2044, SIG-IPE-2045, SIG-IPE-2046
func TestIEDRestrictions(t *testing.T) {
	base := string(mustRead(t, "clause9.scd"))
	cases := []struct{ from, to, want string }{
		{`<IED name="A1KA1">`, `<IED name="None">`, "reserved name None"},
		{`<IED name="A1KA1">`, `<IED name="D1Q1SB4">`, `IED name "D1Q1SB4" is used twice`},
		{`<LN lnClass="CSWI" inst="2" lnType="CSWI_T"/>`, `<LN lnClass="CSWI" inst="1" lnType="CSWI_T"/>`, "LN CSWI1 is defined twice"},
		{`<LN lnClass="MHAI" inst="1" lnType="MHAI_T"/>`, `<LN lnClass="MHAI" inst="1" lnType="CSWI_T"/>`, "is of class CSWI"},
		{`datSet="Positions" confRev="1" uuid="a0e0`, `datSet="Nope" confRev="1" uuid="a0e0`, `data set "Nope" is not defined`},
		{`logName="C1" uuid`, `logName="C9" uuid`, `log "C9"`},
		{`<GSEControl name="ItlPositions" datSet="Positions" appID="Itl" confRev="1"`, `<GSEControl name="ItlPositions" datSet="Positions" appID="Itl" securityEnable="SignatureAndEncryption" confRev="1"`, "not offered by GSESettings McSecurity"},
		{`smvID="11" smpRate="4800" nofASDU="5" confRev="1"`, `smvID="11" smpRate="4800" nofASDU="5"`, "confRev is required for a sampled value"},
		{`<SettingControl numOfSGs="2" actSG="1"/>`, `<SettingControl numOfSGs="2" actSG="3"/>`, "actSG 3 is above numOfSGs 2"},
		{`serviceType="GOOSE" srcCBName="ItlPositions"`, `serviceType="Poll" srcCBName="ItlPositions"`, "serviceType Poll names a source"},
		{`<DAI name="scaleFactor"><Val>200</Val>`, `<DAI name="scaleFactor"><Val>two</Val>`, "is not a number"},
		{`<DAI name="offset">`, `<DAI name="offsetX">`, "sVC.offsetX is not an attribute"},
		{`<DOI name="Mod"><DAI name="ctlModel"><Val>status-only</Val>`, `<DOI name="Mod"><DAI name="ctlModel"><Val>sometimes</Val>`, "not a literal of the enumeration"},
		{`doName="Pos" fc="ST"/>
							<FCDA ldInst="C1" prefix="" lnInst="2"`, `doName="Pos" fc="MX"/>
							<FCDA ldInst="C1" prefix="" lnInst="2"`, "no attribute of the data object has this functional constraint"},
		{`doName="PhV.phsA" daName="cVal.mag.f" fc="MX"`, `doName="PhV.phsA" daName="cVal.mag.f" fc="ST"`, "the attribute's fc is MX"},
		{`<P type="APPID">3000</P>`, `<P type="APPID">30000</P>`, "not four hexadecimal digits"},
		{`<ConnectedAP iedName="A1KA1" apName="S1"/>`, `<ConnectedAP iedName="A1KA1" apName="S2"/>`, "access point S2"},
		{`cbName="Volt" cbUuid`, `cbName="Volts" cbUuid`, "control block C1/Volts which does not exist"},
		{`<DAType id="SVC_T">`, `<DAType id="AV_T">`, `id "AV_T" is used`},
		{`<SDO name="phsC" type="CMV_T"/>`, `<SDO name="phsC" type="WYE_T"/>`, "references itself"},
		{`<EnumVal ord="2">Warning</EnumVal>`, `<EnumVal ord="1">Warning</EnumVal>`, "ord 1 is used twice"},
		{`<ReportControl name="MeasBRCB"`, `<ReportControl name="PosReport"`, `report control block name "PosReport" is used twice`},
		{`<OptFields/>`, ``, "needs at least 1 OptFields"},
		{`<IEDName apRef="S1" apUuid="513d767b-410a-46c6-9afa-f9cea591768e">D1Q1SB4</IEDName>
							<SmvOpts refreshTime="true" sampleSynchronized="true" sampleRate="true"/>`, `<SmvOpts refreshTime="true" sampleSynchronized="true" sampleRate="true"/>
							<IEDName apRef="S1" apUuid="513d767b-410a-46c6-9afa-f9cea591768e">D1Q1SB4</IEDName>`, "IEDName is out of order"},
		{`<RptEnabled max="5">`, `<RptEnabled max="0">`, "max=\"0\""},
	}
	for _, c := range cases {
		if !strings.Contains(base, c.from) {
			t.Fatalf("vector text %q not found", c.from)
		}
		d, err := Parse([]byte(strings.Replace(base, c.from, c.to, 1)))
		if err != nil {
			t.Fatal(err)
		}
		if is := Validate(d, Options{FileType: "SCD"}); !is.Has(c.want) {
			t.Errorf("want %q; got %v", c.want, errorsOf(is))
		}
	}
}

// Covers: SIG-IPE-2047
func TestFileTypes(t *testing.T) {
	d, _ := load(t, "clause9.scd")
	if is := Validate(d, Options{FileType: "ICD"}); !is.Has("exactly one IED") {
		t.Error("ICD rules not applied")
	}
	d, _ = load(t, "ssd_9_2_8.ssd")
	if is := Validate(d, Options{FileType: "SCD"}); !is.Has("contains the IEDs") || !is.Has("Communication section") {
		t.Error("SCD rules not applied")
	}
}

// Covers: SIG-IPE-2033
func TestValueTypes(t *testing.T) {
	for _, c := range []struct{ typ, v string }{
		{"tIEDName", "E1Q1SB1"}, {"tIEDName", "Nonet"}, {"tLDInst", "C1"}, {"tPrefix", ""}, {"tLNInst", "1"},
		{"tAccessPointName", "S1"}, {"tFullDOName", "HPhV.phsAHar(3)"}, {"tFullAttributeName", "crvPts(2).xVal"},
		{"tUUID", "6dacf413-cb9e-4ce8-8a45-7c6325b1afaa"}, {"tMessageID", "E1Q1Switches"}, {"tCDC", "TCS"}, {"tCDC", "XYZ"},
	} {
		if why := types[c.typ](c.v); why != "" {
			t.Errorf("%s %q: %s", c.typ, c.v, why)
		}
	}
	for _, c := range []struct{ typ, v string }{
		{"tIEDName", "None"}, {"tIEDName", "1abc"}, {"tIEDName", strings.Repeat("a", 65)}, {"tLDInst", "_x"}, {"tPrefix", "a b"},
		{"tAccessPointName", strings.Repeat("a", 33)}, {"tFullDOName", " TmASt "}, {"tID", "a b"}, {"tMessageID", ""}, {"tFC", "XX"},
		{"tSclRevision", "CC"}, {"tDataSetName", strings.Repeat("d", 33)},
	} {
		if why := types[c.typ](c.v); why == "" {
			t.Errorf("%s %q accepted", c.typ, c.v)
		}
	}
	for _, c := range []struct{ bt, v, want string }{
		{"INT8", "200", "range"}, {"BOOLEAN", "yes", "boolean"}, {"Timestamp", "2007-12-31T21:01:12.345", ""},
		{"Timestamp", "2007-12-31T21:01:12Z", "time zone"}, {"VisString32", strings.Repeat("x", 33), "longer"}, {"Octet64", "AAEC", ""},
		{"Currency", "INR", ""}, {"INT32U", "4294967295", ""},
	} {
		got := CheckValue(c.bt, c.v, nil)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("CheckValue(%s, %q) = %q", c.bt, c.v, got)
		}
	}
	for _, c := range []struct{ p, v string }{{"IP", "10.0.0.11"}, {"MAC-Address", "01-0C-CD-01-00-02"}, {"APPID", "3001"}, {"VLAN-ID", "123"}, {"VLAN-PRIORITY", "4"}, {"OSI-TSEL", "00000001"}, {"OSI-AP-Title", "1,3,9999,33"}} {
		if why := CheckP(c.p, c.v); why != "" {
			t.Errorf("P %s %q: %s", c.p, c.v, why)
		}
	}
}
