package model

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

func mustModel(t *testing.T) *Model {
	t.Helper()
	needNSD(t)
	m, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Covers: SIG-IPE-1870
func TestCDCTablesPinned(t *testing.T) {
	m := mustModel(t)
	// 7-3 NSD 2007B6: 61 classes, the 10 setting classes with one class per
	// FC variant (27) and an abstract base each (9, ORG has no variants).
	if n := len(m.CDCs); n != 79 {
		t.Fatalf("CDCs: %d, want 79", n)
	}
	abstract, variants, attrs := 0, 0, 0
	for _, c := range m.CDCs {
		if c.Abstract {
			abstract++
		}
		if c.VariantOf != "" {
			variants++
		}
		attrs += len(c.Attrs)
		if c.Kind == "" {
			t.Errorf("%s: no kind", c.Name)
		}
		for _, a := range c.Attrs {
			if a.FC == "" && !a.SubDataObject && !a.ServiceParameter {
				t.Errorf("%s.%s has no FC", c.Name, a.Name)
			}
			if a.Presence == "" && !a.ServiceParameter {
				t.Errorf("%s.%s has no presence", c.Name, a.Name)
			}
		}
	}
	if abstract != 9 || variants != 27 || attrs != 988 {
		t.Fatalf("abstract %d variants %d attributes %d, want 9 27 988", abstract, variants, attrs)
	}
	for _, n := range strings.Fields("SPS DPS INS ENS ACT ACD SEC BCR HST VSS ORS TCS MV CMV SAV WYE DEL SEQ HMV HWYE HDEL SPC DPC INC ENC BSC ISC APC BAC SPG ING ENG ORG TSG CUG VSG ASG CURVE CSG DPL LPL CSD VSD CST BTS UTS LTS GTS MTS NTS STS CTS") {
		if _, ok := m.CDC(n); !ok {
			t.Errorf("missing CDC %s", n)
		}
	}
	// representative rows, one per kind (Tables 17, 30, 40, 49, 74, 85, 90)
	cases := []struct {
		cdc, attr, typ, fc, presence string
		trg                          []string
	}{
		{"SPS", "stVal", "BOOLEAN", "ST", "M", []string{"dchg"}},
		{"SPS", "q", "Quality", "ST", "M", []string{"qchg"}},
		{"SPS", "subVal", "BOOLEAN", "SV", "MFsubst", nil},
		{"DPS", "stVal", "DpStatusKind", "ST", "M", []string{"dchg"}},
		{"INS", "stVal", "INT32", "ST", "M", []string{"dchg", "dupd"}},
		{"ACD", "phsB", "BOOLEAN", "ST", "AllOrNonePerGroup(2)", []string{"dchg"}},
		{"BCR", "actVal", "INT64", "ST", "AllAtLeastOneGroup(2)", []string{"dchg"}},
		{"MV", "mag", "AnalogueValue", "MX", "M", []string{"dchg", "dupd"}},
		{"MV", "sVC", "ScaledValueConfig", "CF", "MFscaledAV", []string{"dchg"}},
		{"MV", "dbRef", "FLOAT32", "CF", "MO(db)", []string{"dchg"}},
		{"CMV", "cVal", "Vector", "MX", "M", []string{"dchg", "dupd"}},
		{"SPC", "stVal", "BOOLEAN", "ST", "MAllOrNonePerGroup(1)", []string{"dchg"}},
		{"SPC", "ctlModel", "CtlModelKind", "CF", "M", []string{"dchg"}},
		{"SPC", "sboTimeout", "INT32U", "CF", "MOsbo", []string{"dchg"}},
		{"SPC", "operTimeout", "INT32U", "CF", "MOenhanced", []string{"dchg"}},
		{"APC", "mxVal", "AnalogueValue", "MX", "MAllOrNonePerGroup(1)", []string{"dchg"}},
		{"APC", "dbRef", "FLOAT32", "CF", "MO(db)", []string{"dchg"}}, // OCR had M (F-1154)
		{"SPG_SP", "setVal", "BOOLEAN", "SP", "M", []string{"dchg"}},
		{"SPG_SG", "setVal", "BOOLEAN", "SG", "M", nil},
		{"ASG_SP", "setMag", "AnalogueValueCtl", "SP", "M", []string{"dchg"}},
		{"ORG", "setTstCB", "ObjectReference", "SP", "OF(setTstRef)", []string{"dchg"}},
		{"DPL", "vendor", "VisString255", "DC", "M", nil},
		{"LPL", "ldNs", "VisString255", "EX", "MFln0", nil},
		{"LPL", "configRev", "VisString255", "DC", "MOln0", nil},
		{"BTS", "entryID", "EntryID", "SR", "M", nil},
		{"CST", "objRef", "ObjectReference", "SR", "M", []string{"dupd"}},
	}
	for _, c := range cases {
		a, ok := m.FindAttr(c.cdc, c.attr)
		if !ok {
			t.Errorf("%s.%s missing", c.cdc, c.attr)
			continue
		}
		if a.Type != c.typ || a.FC != c.fc || a.Presence != c.presence || !reflect.DeepEqual(a.TrgOp, c.trg) {
			t.Errorf("%s.%s = %s %s %s %v, want %s %s %s %v", c.cdc, c.attr, a.Type, a.FC, a.Presence, a.TrgOp, c.typ, c.fc, c.presence, c.trg)
		}
	}
	// defaults; value ranges come with the constructed attribute members
	// only (the NSD has no ranges for CDC attributes, see F-1157)
	if a, _ := m.FindAttr("SPC", "sboClass"); a.Default != "operate-once" {
		t.Errorf("SPC.sboClass default %q", a.Default)
	}
	for _, c := range []struct{ typ, attr, want string }{
		{"RangeConfig", "limDb", "[0...100000]"},
		{"ValWithTrans", "posVal", "[-64...63]"},
	} {
		var got string
		for _, a := range m.AttrTypes[c.typ].Attrs {
			if a.Name == c.attr {
				got = a.Range
			}
		}
		if got != c.want {
			t.Errorf("%s.%s range = %q, want %q", c.typ, c.attr, got, c.want)
		}
	}
	// sub data objects of composed classes
	if a, _ := m.CDCs["WYE"].Attr("phsA"); !a.SubDataObject || a.Type != "CMV" {
		t.Errorf("WYE.phsA = %+v", a)
	}
	if a, _ := m.CDCs["HMV"].Attr("har"); !a.Array || a.Type != "CMV" || a.MaxIndex != "maxPts-1" {
		t.Errorf("HMV.har = %+v", a)
	}
}

// Covers: SIG-IPE-1871
func TestConstructedAttributeClasses(t *testing.T) {
	m := mustModel(t)
	want := map[string][]string{ // 7-3 Tables 1-13
		"ScaledValueConfig": {"scaleFactor", "offset"}, "RangeConfig": {"hhLim", "hLim", "lLim", "llLim", "min", "max", "limDb"},
		"ValWithTrans": {"posVal", "transInd"}, "PulseConfig": {"cmdQual", "onDur", "offDur", "numPls"}, "Unit": {"SIUnit", "multiplier"},
		"Vector": {"mag", "ang"}, "Point": {"xVal", "yVal", "zVal"}, "Cell": {"xStart", "xEnd", "yStart", "yEnd"},
		"CalendarTime": {"occ", "occType", "occPer", "weekDay", "month", "day", "hr", "mn"}, "AnalogueValue": {"i", "f"},
		"AnalogueValueCtl": {"i", "f"}, "AnalogueValueCtlF": {"f"}, "AnalogueValueCtlInt": {"i"},
	}
	for n, attrs := range want {
		at, ok := m.AttrTypes[n]
		if !ok {
			t.Errorf("missing %s", n)
			continue
		}
		var got []string
		for _, a := range at.Attrs {
			got = append(got, a.Name)
		}
		if !reflect.DeepEqual(got, attrs) {
			t.Errorf("%s: %v, want %v", n, got, attrs)
		}
	}
	u := m.AttrTypes["Unit"]
	if u.Attrs[0].Type != "SIUnitKind" || u.Attrs[0].Presence != "M" || u.Attrs[1].Type != "MultiplierKind" || u.Attrs[1].Presence != "O" {
		t.Errorf("Unit = %+v", u.Attrs)
	}
	if a := m.AttrTypes["AnalogueValue"].Attrs; a[0].Presence != "AtLeastOne(1)" || a[1].Presence != "AtLeastOne(1)" {
		t.Errorf("AnalogueValue presence %+v", a)
	}
	if a := m.AttrTypes["AnalogueValueCtl"].Attrs; a[0].Presence != "AllOnlyOneGroup(1)" || a[1].Presence != "AllOnlyOneGroup(2)" {
		t.Errorf("AnalogueValueCtl presence %+v", a)
	}
	if a := m.AttrTypes["Vector"].Attrs[1]; a.Range != "[-180...180]" {
		t.Errorf("Vector.ang range %q", a.Range)
	}
	// Quality bit order (7-2 6.2, mapped by 8-1): validity 0-1 … operatorBlocked 12
	q := m.AttrTypes["Quality"]
	bits := map[string]string{}
	for _, a := range q.Attrs {
		bits[a.Name] = a.Bits
	}
	for n, b := range map[string]string{"validity": "0-1", "detailQual.overflow": "2", "detailQual.oldData": "7", "detailQual.inaccurate": "9", "source": "10", "test": "11", "operatorBlocked": "12"} {
		if bits[n] != b {
			t.Errorf("Quality %s bits %q, want %q", n, bits[n], b)
		}
	}
	if o := m.AttrTypes["Originator"]; o.Attrs[0].Type != "OriginatorCategoryKind" || o.Attrs[1].Type != "Octet64" {
		t.Errorf("Originator %+v", o.Attrs)
	}
}

// Covers: SIG-IPE-1872
func TestEnumerations73(t *testing.T) {
	m := mustModel(t)
	n := map[string]int{}
	for _, e := range m.Enums {
		n[e.Source]++
	}
	// 7-2: 5 from the NSD, 4 packed kinds from text.yaml
	if n["7-3"] != 19 || n["7-4"] != 62 || n["7-2"] != 9 {
		t.Fatalf("enumerations per source %v, want 7-3:19 7-4:62 7-2:9", n)
	}
	lit := func(e string, v int) string {
		s, ok := m.Enums[e].Literal(v)
		if !ok {
			t.Errorf("%s has no %d", e, v)
		}
		return s
	}
	for _, c := range []struct {
		enum string
		v    int
		want string
	}{
		{"CtlModelKind", 0, "status-only"}, {"CtlModelKind", 4, "sbo-with-enhanced-security"}, {"SboClassKind", 1, "operate-many"},
		{"SIUnitKind", 1, ""}, {"SIUnitKind", 5, "A"}, {"SIUnitKind", 23, "°C"}, {"SIUnitKind", 29, "V"}, {"SIUnitKind", 38, "W"},
		{"SIUnitKind", 61, "VA"}, {"SIUnitKind", 63, "VAr"}, {"SIUnitKind", 65, "cos(phi)"}, {"SIUnitKind", 72, "Wh"}, {"SIUnitKind", 89, "A/Vs"},
		{"MultiplierKind", -6, "µ"}, {"MultiplierKind", 0, ""}, {"MultiplierKind", 3, "k"}, {"MultiplierKind", 6, "M"}, {"MultiplierKind", 24, "Y"},
		{"CurveCharKind", 16, "Reserved"}, {"CurveCharKind", 48, "Multiline 16"}, {"RangeKind", 3, "high-high"},
		{"PhaseAngleReferenceKind", 11, "Synchrophasor"}, {"WeekdayKind", 7, "Sunday"}, {"OutputSignalKind", 2, "persistent-feedback"},
		{"DpStatusKind", 2, "on"}, {"ValidityKind", 3, "questionable"}, {"OriginatorCategoryKind", 3, "remote-control"},
	} {
		if got := lit(c.enum, c.v); got != c.want {
			t.Errorf("%s(%d) = %q, want %q", c.enum, c.v, got, c.want)
		}
	}
	if len(m.Enums["SIUnitKind"].Items) != 79 || len(m.Enums["MultiplierKind"].Items) != 21 || len(m.Enums["CurveCharKind"].Items) != 49 {
		t.Errorf("SIUnitKind %d MultiplierKind %d CurveCharKind %d items", len(m.Enums["SIUnitKind"].Items), len(m.Enums["MultiplierKind"].Items), len(m.Enums["CurveCharKind"].Items))
	}
	if _, ok := m.Enums["SIUnitKind"].Literal(40); ok {
		t.Error("SIUnitKind 40 is not defined")
	}
}

// Covers: SIG-IPE-1873
func TestLNClassesPinned(t *testing.T) {
	m := mustModel(t)
	// classes of the NSD that data/text.yaml has no title for
	untitled := map[string]bool{}
	for _, n := range strings.Fields(untitledLNs) {
		untitled[n] = true
	}
	abstract, concrete, dos := 0, 0, 0
	groups := map[string]int{}
	for _, l := range m.LNs {
		if l.Abstract {
			abstract++
		} else {
			concrete++
			groups[l.Group]++
			if testDescsOK && l.Title == "" && !untitled[l.Name] {
				t.Errorf("%s has no title", l.Name)
			}
		}
		dos += len(l.DataObjects)
	}
	// 7-4 NSD 2007B6: 39 abstract and 165 concrete classes
	if abstract != 39 || concrete != 165 || dos != 6277 {
		t.Fatalf("abstract %d concrete %d data objects %d, want 39 165 6277", abstract, concrete, dos)
	}
	want := map[string]int{"L": 8, "A": 5, "C": 6, "F": 11, "G": 4, "I": 6, "K": 5, "M": 14, "P": 32, "Q": 6, "R": 11, "S": 12, "T": 20, "X": 3, "Y": 4, "Z": 18}
	if !reflect.DeepEqual(groups, want) {
		t.Errorf("groups %v, want %v", groups, want)
	}
	if got := m.LNClassNames("X"); !reflect.DeepEqual(got, []string{"XCBR", "XFUS", "XSWI"}) {
		t.Errorf("group X: %v", got)
	}
	for _, c := range []struct {
		ln, do, cdc, pres, presDs, enum string
		n                               int
	}{
		{"XCBR", "Pos", "DPC", "M", "F", "", 40},
		{"XCBR", "Loc", "SPS", "M", "F", "", 40},
		{"XCBR", "OpCnt", "INS", "M", "O", "", 40},
		{"XCBR", "CBOpCap", "ENS", "O", "F", "BreakerOpCapabilityKind", 40},
		{"XCBR", "Beh", "ENS", "M", "M", "BehaviourModeKind", 40},
		{"MMXU", "TotW", "MV", "O", "O", "", 61},
		{"MMXU", "PhV", "WYE", "O", "O", "", 61},
		{"MMXU", "PPV", "DEL", "O", "O", "", 61},
		{"LLN0", "Mod", "ENC", "MOrootLD", "na", "BehaviourModeKind", 13},
		{"LPHD", "PhyHealth", "ENS", "M", "na", "HealthKind", 16},
		{"LPHD", "Proxy", "SPS", "M", "na", "", 16},
		{"CSWI", "LocKey", "SPS", "OF(Loc)", "F", "", 35},
		{"GGIO", "Ind", "SPS", "Omulti", "F", "", 38},
		{"PTOC", "Str", "ACD", "M", "F", "", 37},
		{"PTOC", "TmAChr", "CSG", "OmultiRange(33,48)", "F", "", 37},
		{"PTRC", "Tr", "ACT", "AtLeastOne(1)", "F", "", 0},
		{"CCGR", "ClTmpIn", "MV", "AllOnlyOneGroup(2)", "O", "", 0},
		{"FPID", "PAct", "MV", "OFcond(1)", "O", "", 0},
		{"PDIS", "K0Fact", "ASG", "O", "F", "", 0},
		{"MSQI", "DQ0Seq", "SEQ", "O", "O", "", 0},
	} {
		l, ok := m.LNClass(c.ln)
		if !ok {
			t.Errorf("missing %s", c.ln)
			continue
		}
		if c.n != 0 && len(l.DataObjects) != c.n {
			t.Errorf("%s: %d data objects, want %d", c.ln, len(l.DataObjects), c.n)
		}
		d, ok := l.DataObject(c.do)
		if !ok {
			t.Errorf("%s.%s missing", c.ln, c.do)
			continue
		}
		if d.CDC != c.cdc || d.Pres != c.pres || d.PresDs != c.presDs || d.Enum != c.enum {
			t.Errorf("%s.%s = %s %s/%s %s, want %s %s/%s %s", c.ln, c.do, d.CDC, d.Pres, d.PresDs, d.Enum, c.cdc, c.pres, c.presDs, c.enum)
		}
	}
	if d, _ := m.LNs["LLN0"].DataObject("LEDRs"); !d.Transient {
		t.Error("LLN0.LEDRs is transient")
	}
	if l := m.LNs["XCBR"]; testDescsOK && l.Title != "Circuit breaker" || l.Group != "X" {
		t.Errorf("XCBR %q %s", l.Title, l.Group)
	}
	// MMXU.W is in the NSD; the OCR tables had lost it (F-1151)
	if _, ok := m.LNs["MMXU"].DataObject("W"); !ok {
		t.Error("MMXU.W missing")
	}
}

// Covers: SIG-IPE-1874
func TestEnumerations74(t *testing.T) {
	m := mustModel(t)
	for _, c := range []struct {
		enum string
		v    int
		want string
	}{
		{"BehaviourModeKind", 1, "on"}, {"BehaviourModeKind", 4, "test/blocked"}, {"BehaviourModeKind", 5, "off"},
		{"HealthKind", 1, "Ok"}, {"HealthKind", 3, "Alarm"}, {"PIDAlgorithmKind", 2, "I"}, {"CalcMethodKind", 13, "DIFF"},
		{"FuseFunctionKind", 99, "Other"}, {"TransientPerformanceClassKind", 10, "TPS"}, {"WeakEndInfeedModeKind", 4, "Echo and Operate"},
		{"SetpointEndKind", 4, "Cancelled: loss of communication with dispatch centre"}, {"VoltInterruptDetectionKind", 7, "Normally Closed breaker contact"},
	} {
		e, ok := m.Enum(c.enum)
		if !ok {
			t.Errorf("missing %s", c.enum)
			continue
		}
		if got, _ := e.Literal(c.v); got != c.want {
			t.Errorf("%s(%d) = %q, want %q", c.enum, c.v, got, c.want)
		}
	}
	// every ENS/ENC/ENG data object names an enumeration of the model
	for _, l := range m.LNs {
		for _, d := range l.DataObjects {
			if (d.CDC == "ENS" || d.CDC == "ENC" || d.CDC == "ENG") && d.Enum == "" {
				t.Errorf("%s.%s has no enumeration", l.Name, d.Name)
			}
		}
	}
	if v, ok := m.Enums["BehaviourModeKind"].Value("Test/Blocked"); !ok || v != 4 {
		t.Errorf("case-insensitive literal lookup: %d %v", v, ok)
	}
}

// Covers: SIG-IPE-1875
func TestPresenceConditionsKnown(t *testing.T) {
	m := mustModel(t)
	for _, p := range []string{"M", "O", "F", "na", "Omulti", "AtLeastOne(3)", "MO(db)", "MOcond(2)", "OF(Loc)", "OmultiRange(33,48)", "MFsubst", "MOrootLD"} {
		if m.presenceCode(p) == "" {
			t.Errorf("%s not recognised", p)
		}
	}
	for _, p := range []string{"X", "Mx(1", ""} {
		if m.presenceCode(p) != "" {
			t.Errorf("%q recognised", p)
		}
	}
	for _, fc := range []string{"ST", "MX", "SP", "SV", "CF", "DC", "SG", "SE", "SR", "OR", "BL", "EX", "CO"} {
		if _, ok := m.FCs[fc]; !ok {
			t.Errorf("FC %s missing", fc)
		}
	}
}

// Covers: SIG-IPE-1876
func TestParseRef(t *testing.T) {
	for _, c := range []struct {
		in                     string
		ld, prefix, class, in2 string
		path                   []string
		fc                     string
	}{
		{"LD0/Q0XCBR1.Pos.stVal", "LD0", "Q0", "XCBR", "1", []string{"Pos", "stVal"}, ""},
		{"LD0/MMXU1$MX$TotW$mag$f", "LD0", "", "MMXU", "1", []string{"TotW", "mag", "f"}, "MX"},
		{"LD0/LLN0.Mod", "LD0", "", "LLN0", "", []string{"Mod"}, ""},
		{"GGIO12.Ind3.stVal", "", "", "GGIO", "12", []string{"Ind3", "stVal"}, ""},
		{"LD0/HST1.hstVal[3]", "LD0", "", "HST", "1", []string{"hstVal[3]"}, ""},
	} {
		r, err := ParseRef(c.in)
		if c.class == "HST" {
			if err == nil {
				// "HST1" is only three letters of class: a syntax error, not a class HST
				t.Errorf("%s: want syntax error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if r.LD != c.ld || r.Prefix != c.prefix || r.Class != c.class || r.Inst != c.in2 || !reflect.DeepEqual(r.Path, c.path) || r.FC != c.fc {
			t.Errorf("%s = %+v", c.in, r)
		}
	}
	for _, bad := range []string{"", "/XCBR1.Pos", "LD0/XC1.Pos", "LD0/XCBR1..Pos", "LD0/xcbr1.Pos"} {
		if _, err := ParseRef(bad); !errors.Is(err, ErrSyntax) {
			t.Errorf("%q: %v, want syntax error", bad, err)
		}
	}
}

// Covers: SIG-IPE-1877
func TestValidatePositive(t *testing.T) {
	m := mustModel(t)
	for _, c := range []struct {
		ref, fc, leaf, enum string
	}{
		{"LD0/Q0XCBR1.Pos.stVal", "ST", "DpStatusKind", "DpStatusKind"},
		{"LD0/Q0XCBR1.Pos.q", "ST", "Quality", ""},
		{"LD0/Q0XCBR1.Pos.q.validity", "ST", "ValidityKind", "ValidityKind"},
		{"LD0/Q0XCBR1.Pos.q.detailQual.oldData", "ST", "BOOLEAN", ""},
		{"LD0/Q0XCBR1.Pos.origin.orCat", "ST", "OriginatorCategoryKind", "OriginatorCategoryKind"},
		{"LD0/Q0XCBR1.Pos.ctlModel", "CF", "CtlModelKind", "CtlModelKind"},
		{"LD0/Q0XCBR1.Pos.Oper.ctlVal", "CO", "BOOLEAN", ""},
		{"LD0/Q0XCBR1.Pos.Oper.origin.orIdent", "CO", "Octet64", ""},
		{"LD0/Q0XCBR1$CO$Pos$SBOw$Check", "", "CheckConditions", ""},
		{"LD0/Q0XCBR1.Pos.SBO", "CO", "ObjectReference", ""},
		{"LD0/Q0XCBR1.Beh.stVal", "ST", "EnumDA", "BehaviourModeKind"},
		{"LD0/Q0XCBR1.Mod.Oper.ctlVal", "CO", "EnumDA", "BehaviourModeKind"},
		{"LD0/MMXU1.TotW.mag.f", "MX", "FLOAT32", ""},
		{"LD0/MMXU1$MX$TotW$mag$f", "", "FLOAT32", ""},
		{"LD0/MMXU1.TotW.units.SIUnit", "CF", "SIUnitKind", "SIUnitKind"},
		{"LD0/MMXU1.TotW.units.multiplier", "CF", "MultiplierKind", "MultiplierKind"},
		{"LD0/MMXU1.PhV.phsA.cVal.mag.f", "MX", "FLOAT32", ""},
		{"LD0/MMXU1.PhV.phsA.cVal.ang.f", "MX", "FLOAT32", ""},
		{"LD0/MMXU1.PhV.angRef", "CF", "PhaseAngleReferenceKind", "PhaseAngleReferenceKind"},
		{"LD0/GGIO1.Ind3.stVal", "ST", "BOOLEAN", ""},
		{"LD0/GGIO1.AnOut2.Oper.ctlVal.f", "CO", "FLOAT32", ""},
		{"LD0/PTOC1.StrVal.setMag.f", "SG", "FLOAT32", ""},
		{"LD0/PTOC1.StrVal.setMag.f", "SE", "FLOAT32", ""},
		{"LD0/PTOC1.OpDlTmms.setVal", "SP", "INT32", ""},
		{"LD0/PTOC1.Str.dirGeneral", "ST", "FaultDirectionKind", "FaultDirectionKind"},
		{"LD0/LPHD1.PhyNam.vendor", "DC", "VisString255", ""},
		{"LD0/LLN0.NamPlt.configRev", "DC", "VisString255", ""},
		{"LD0/XCBR1.SumSwARs.actVal", "ST", "INT64", ""},
	} {
		r, err := m.Validate(c.ref, c.fc)
		if err != nil {
			t.Errorf("%s [%s]: %v", c.ref, c.fc, err)
			continue
		}
		if r.Leaf != c.leaf || r.Enum != c.enum {
			t.Errorf("%s [%s]: leaf %q enum %q, want %q %q", c.ref, c.fc, r.Leaf, r.Enum, c.leaf, c.enum)
		}
	}
	// a data object reference: FCs of its attributes
	r, err := m.Validate("LD0/Q0XCBR1.Pos", "ST")
	if err != nil {
		t.Fatal(err)
	}
	for _, fc := range []string{"ST", "OR", "SV", "BL", "CF", "DC", "EX", "CO"} {
		if !contains(r.FCs, fc) {
			t.Errorf("Pos FCs %v lack %s", r.FCs, fc)
		}
	}
	if r, _ := m.Validate("LD0/MMXU1.PhV.phsA", "MX"); r == nil || r.CDC.Name != "CMV" || !reflect.DeepEqual(r.DOPath, []string{"PhV", "phsA"}) {
		t.Errorf("sub data object: %+v", r)
	}
}

// Covers: SIG-IPE-1878
func TestValidateNegative(t *testing.T) {
	m := mustModel(t)
	for _, c := range []struct {
		ref, fc string
		want    error
	}{
		{"LD0/ABCD1.Pos", "ST", ErrUnknownLNClass},
		{"LD0/DomainLN1.Beh", "ST", ErrSyntax},
		{"LD0/XCBR1.TotW.mag.f", "MX", ErrUnknownDO},
		{"LD0/XCBR1.Pos.mag", "ST", ErrUnknownDA},
		{"LD0/XCBR1.Pos.stVal", "MX", ErrFCMismatch},
		{"LD0/XCBR1.Pos.ctlModel", "ST", ErrFCMismatch},
		{"LD0/XCBR1$ST$Pos$stVal", "MX", ErrFCMismatch},
		{"LD0/XCBR1.Pos.stVal", "ZZ", ErrUnknownFC},
		{"LD0/XCBR1.Pos.Oper.foo", "CO", ErrUnknownDA},
		{"LD0/XCBR1.Pos.Oper.ctlVal", "ST", ErrFCMismatch},
		{"LD0/XCBR1.Loc.Oper.ctlVal", "CO", ErrUnknownDA},
		{"LD0/XCBR1.Pos.ctlVal", "CO", ErrUnknownDA},
		{"LD0/MMXU1.TotW.mag.x", "MX", ErrUnknownDA},
		{"LD0/MMXU1.TotW1.mag.f", "MX", ErrUnknownDO},
		{"LD0/MMXU1.TotW", "ST", ErrFCMismatch},
		{"LD0/PTOC1.OpDlTmms.setVal", "ST", ErrFCMismatch},
		{"LD0/MMXU1$CO$Oper$TotW", "", ErrSyntax},
	} {
		_, err := m.Validate(c.ref, c.fc)
		if !errors.Is(err, c.want) {
			t.Errorf("%s [%s]: %v, want %v", c.ref, c.fc, err, c.want)
		}
	}
}

// Covers: SIG-IPE-1879
func TestControlModels(t *testing.T) {
	m := mustModel(t)
	want := map[string]string{"SPC": "BOOLEAN", "DPC": "BOOLEAN", "INC": "INT32", "ENC": "EnumDA", "BSC": "StepControlKind", "ISC": "INT8", "APC": "AnalogueValueCtl", "BAC": "StepControlKind"}
	for _, n := range m.CDCNames() {
		ci, _ := m.Control(n)
		if typ, ok := want[n]; ok != ci.Controllable || ok && ci.CtlValType != typ {
			t.Errorf("%s: controllable %v ctlVal %q", n, ci.Controllable, ci.CtlValType)
		}
		if !ci.Controllable && !reflect.DeepEqual(ci.Models, []string{"status-only"}) {
			t.Errorf("%s models %v", n, ci.Models)
		}
	}
	ci, _ := m.Control("SPC")
	if len(ci.Models) != 5 || len(ci.OperFields) != 7 || len(ci.CancelFields) != 6 || ci.OperFields[6].Name != "Check" {
		t.Errorf("SPC %+v", ci)
	}
	for model, seq := range map[string][]Service{
		"status-only":                   nil,
		"direct-with-normal-security":   {SvcOperate},
		"2":                             {SvcSelect, SvcOperate},
		"direct-with-enhanced-security": {SvcOperate, SvcCommandTermination},
		"sbo-with-enhanced-security":    {SvcSelectWithValue, SvcOperate, SvcCommandTermination},
	} {
		got, err := ci.Sequence(model)
		if err != nil || !reflect.DeepEqual(got, seq) {
			t.Errorf("%s: %v %v", model, got, err)
		}
	}
	if _, err := ci.Sequence("5"); err == nil {
		t.Error("model 5 accepted")
	}
	for model, attrs := range map[string][]string{
		"direct-with-normal-security": {"ctlModel"},
		"sbo-with-normal-security":    {"stSeld", "ctlModel", "sboTimeout"},
		"sbo-with-enhanced-security":  {"stSeld", "ctlModel", "sboTimeout", "operTimeout"},
	} {
		got, err := m.RequiredAttrs("DPC", model)
		if err != nil || !reflect.DeepEqual(got, attrs) {
			t.Errorf("DPC %s: %v %v", model, got, err)
		}
	}
}

// Covers: SIG-IPE-1880
func TestDescribeAndUnits(t *testing.T) {
	m := mustModel(t)
	for _, c := range []struct{ name, want string }{
		{"TotW", "total active power"}, {"PhV", "phase to ground voltage"}, {"ClcExp", "calculation expired"},
		{"OpDlTmms", "operate delay time in milliseconds"}, {"Pos", "position"}, {"Hz", "frequency"}, {"BlkRef", "block reference"},
	} {
		if got := m.Words(c.name); got != c.want {
			t.Errorf("Words(%s) = %q, want %q", c.name, got, c.want)
		}
	}
	d, err := m.Describe("XCBR", "Pos")
	if err != nil || d.CDC != "DPC" || d.Kind != "controllable" || !d.Mandatory || testDescsOK && d.LNTitle != "Circuit breaker" {
		t.Errorf("XCBR.Pos: %+v %v", d, err)
	}
	d, _ = m.Describe("LLN0", "Mod")
	if d.Enum != "BehaviourModeKind" || !reflect.DeepEqual(d.Literals, []string{"on", "blocked", "test", "test/blocked", "off"}) {
		t.Errorf("LLN0.Mod: %+v", d)
	}
	if !strings.Contains(d.String(), "values on, blocked") {
		t.Errorf("String: %s", d.String())
	}
	if d, err := m.Describe("GGIO", "Ind7"); err != nil || !d.Multi {
		t.Errorf("GGIO.Ind7: %+v %v", d, err)
	}
	if _, err := m.Describe("XCBR", "TotW"); !errors.Is(err, ErrUnknownDO) {
		t.Errorf("XCBR.TotW: %v", err)
	}
	for _, c := range []struct {
		u, mult int
		sym     string
	}{{29, 3, "kV"}, {38, 6, "MW"}, {5, 0, "A"}, {33, 0, "Hz"}, {23, 0, "°C"}, {1, -2, "c"}, {63, 6, "MVAr"}, {72, 3, "kWh"}} {
		s, err := m.UnitSymbol(c.u, c.mult)
		if err != nil || s != c.sym {
			t.Errorf("UnitSymbol(%d,%d) = %q %v, want %q", c.u, c.mult, s, err, c.sym)
		}
		if c.u == 1 {
			continue
		}
		u, mu, err := m.ParseUnit(c.sym)
		if err != nil || u != c.u || mu != c.mult {
			t.Errorf("ParseUnit(%q) = %d %d %v", c.sym, u, mu, err)
		}
	}
	if u, mu, _ := m.ParseUnit("min"); u != 85 || mu != 0 {
		t.Errorf("min = %d %d, want minutes", u, mu)
	}
	if u, mu, _ := m.ParseUnit("mA"); u != 5 || mu != -3 {
		t.Errorf("mA = %d %d", u, mu)
	}
	if _, _, err := m.ParseUnit("furlong"); err == nil {
		t.Error("furlong parsed")
	}
	if _, err := m.UnitSymbol(40, 0); err == nil {
		t.Error("SIUnit 40 accepted")
	}
}

// Covers: SIG-IPE-1881
func TestMandatoryDataObjects(t *testing.T) {
	m := mustModel(t)
	names := func(ds []DataObject) []string {
		var out []string
		for _, d := range ds {
			out = append(out, d.Name)
		}
		return out
	}
	for _, c := range []struct {
		ln   string
		ds   bool
		want []string
	}{
		{"XCBR", false, []string{"Loc", "OpCnt", "Beh", "Pos", "BlkOpn", "BlkCls"}},
		{"XCBR", true, []string{"Beh", "ClcMth", "ClcSrc"}},
		{"LLN0", false, []string{"Beh"}},
		{"LPHD", false, []string{"PhyNam", "PhyHealth", "Proxy"}},
		{"PTOC", false, []string{"Str", "Op", "Beh"}},
		{"MMXU", false, []string{"Beh"}},
	} {
		got, err := m.MandatoryDataObjects(c.ln, c.ds)
		if err != nil || !reflect.DeepEqual(names(got), c.want) {
			t.Errorf("%s ds=%v: %v %v, want %v", c.ln, c.ds, names(got), err, c.want)
		}
	}
	if _, err := m.MandatoryDataObjects("NOPE", false); !errors.Is(err, ErrUnknownLNClass) {
		t.Errorf("unknown class: %v", err)
	}
	// every concrete LN class but LPHD has Beh mandatory (inherited from DomainLN)
	for _, l := range m.LNs {
		if l.Name == "LPHD" {
			continue
		}
		if d, ok := l.DataObject("Beh"); !l.Abstract && (!ok || d.Pres != "M") {
			t.Errorf("%s.Beh: %+v", l.Name, d)
		}
	}
}

// Covers: SIG-IPE-1885
func TestLoadRejectsBrokenTables(t *testing.T) {
	needNSD(t)
	read := func(n string) []byte {
		b, err := dataFS.ReadFile("data/" + n)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	base := func() fstest.MapFS {
		fs := fstest.MapFS{}
		for _, n := range []string{"text.yaml", "bap.yaml"} {
			fs["data/"+n] = &fstest.MapFile{Data: read(n)}
		}
		return fs
	}
	if _, err := Load(base()); err != nil {
		t.Fatalf("embedded tables: %v", err)
	}
	edit := func(file, old, new string) func(fs fstest.MapFS) {
		return func(fs fstest.MapFS) {
			s := string(fs["data/"+file].Data)
			if !strings.Contains(s, old) {
				t.Fatalf("%s lacks %q", file, old)
			}
			fs["data/"+file].Data = []byte(strings.Replace(s, old, new, 1))
		}
	}
	for name, f := range map[string]func(fs fstest.MapFS){
		"title of a class the NSD lacks":   func(fs fstest.MapFS) { appendText(fs, "lnTitles:\n  XCBQ: \"breaker\"\n") },
		"abbreviation the NSD lacks":       func(fs fstest.MapFS) { appendText(fs, "abbreviations:\n  Abz: \"absolute\"\n") },
		"CDC without kind":                 edit("text.yaml", "status: [SPS, ", "status: ["),
		"FC without meaning":               edit("text.yaml", "  ST: ", "  XX: "),
		"presence condition without words": edit("text.yaml", "  MOsbo: ", "  MOsbx: "),
		"BAP data object not in 7-4":       edit("bap.yaml", "do: OpDlTmms", "do: OpDlTm"),
		"missing file":                     func(fs fstest.MapFS) { delete(fs, "data/text.yaml") },
	} {
		fs := base()
		f(fs)
		if _, err := Load(fs); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if len(nsdTablesOf().ASDs) > 0 {
		fs := base()
		edit("bap.yaml", `asd: "Reverse Blocking_0_1.asd"`, `asd: "nope.asd"`)(fs)
		if _, err := Load(fs); err == nil {
			t.Errorf("BAP without its ASD file: loaded")
		}
	}
}

// appendText adds YAML to the supplement of fs.
func appendText(fs fstest.MapFS, s string) {
	fs["data/text.yaml"].Data = append(append([]byte(nil), fs["data/text.yaml"].Data...), "\n"+s...)
}

// Covers: SIG-IPE-1885
// TestSetDescriptionsChecked: titles and abbreviations given by the
// application are checked against the loaded name space definitions, and
// the default model is rebuilt with them.
func TestSetDescriptionsChecked(t *testing.T) {
	needNSD(t)
	descMu.RLock()
	ln, ab := copyMap(descLN), copyMap(descAbbr)
	descMu.RUnlock()
	t.Cleanup(func() { SetDescriptions(ln, ab) })
	SetDescriptions(map[string]string{"XCBR": "breaker"}, map[string]string{"Pos": "position"})
	m, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := m.LNClass("XCBR"); c.Title != "breaker" || m.Abbrev["Pos"] != "position" {
		t.Errorf("title %q abbreviation %q", c.Title, m.Abbrev["Pos"])
	}
	SetDescriptions(map[string]string{"XCBQ": "breaker"}, nil)
	if _, err := Default(); err == nil {
		t.Error("a title of a class the NSD lacks was accepted")
	}
}

// TestNoNSD: without name space definitions the model reports ErrNoNSD
// instead of an empty model.
func TestNoNSD(t *testing.T) {
	nsdMu.Lock()
	saved := nsdData
	nsdData = nil
	nsdMu.Unlock()
	defMu.Lock()
	savedM := defM
	defM = nil
	defMu.Unlock()
	t.Cleanup(func() {
		nsdMu.Lock()
		nsdData = saved
		nsdMu.Unlock()
		defMu.Lock()
		defM = savedM
		defMu.Unlock()
	})
	if _, err := Default(); !errors.Is(err, ErrNoNSD) {
		t.Errorf("Default without NSD: %v", err)
	}
	if err := SetNSDJSON([]byte(`{}`)); err == nil {
		t.Error("empty tables accepted")
	}
}

// TestNSDJSONRoundTrip: the JSON form of the tables loads to the same
// model as IEC's files.
func TestNSDJSONRoundTrip(t *testing.T) {
	needNSD(t)
	nsdMu.RLock()
	saved := nsdData
	nsdMu.RUnlock()
	t.Cleanup(func() { installNSD(saved) })
	before := mustModel(t)
	js := (&NSDTables{saved}).JSON()
	if err := SetNSDJSON(js); err != nil {
		t.Fatal(err)
	}
	after := mustModel(t)
	if !reflect.DeepEqual(before.LNClassNames(""), after.LNClassNames("")) || !reflect.DeepEqual(before.CDCNames(), after.CDCNames()) || len(before.Enums) != len(after.Enums) {
		t.Error("the JSON form builds a different model")
	}
}

// untitledLNs are concrete LN classes without a title in data/text.yaml
// (none: every concrete class of the 7-4 NSD has one).
const untitledLNs = ""
