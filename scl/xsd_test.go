package scl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cB-Sigma/iec61850/internal/testpki"
)

// codeComponent is the directory of IEC's SCL schema zip (IEC 61850-6
// SCL.2007C5) under $IEC61850_CODE_COMPONENTS (the test is skipped
// without it).
func codeComponent(t testing.TB) string {
	return testpki.SpecData(t, 3, "IEC_61850-6.SCL.2007C5")
}

func official(t *testing.T, name string) (*Document, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(codeComponent(t), name))
	if err != nil {
		t.Fatal(err)
	}
	d, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return d, string(raw)
}

func validateText(t *testing.T, src string) Issues {
	t.Helper()
	d, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return Validate(d, Options{})
}

func schemaIssues(is Issues) []string {
	var out []string
	for _, i := range is {
		if i.Clause == "XSD" {
			out = append(out, i.String())
		}
	}
	return out
}

// Covers: SIG-IPE-2072
func TestOfficialExamples(t *testing.T) {
	needSchema(t)
	if SchemaVersion() != "2007C5" {
		t.Fatalf("schema %s", SchemaVersion())
	}
	// 9.2.8: no departure at all
	d, _ := official(t, "9.2.8 - Susbtation example.ssd")
	if is := Validate(d, Options{FileType: "SSD"}); len(is) != 0 {
		t.Errorf("9.2.8 example: %v", is)
	}
	// Annex D: valid by the XSD; the two errors are the confRev our reading
	// of 9.3.10 and 9.3.11 requires and the example omits (F-1162)
	d, _ = official(t, "Annex D - SCL example.scd")
	is := Validate(d, Options{FileType: "SCD"})
	if s := schemaIssues(is); len(s) != 0 {
		t.Errorf("Annex D against the XSD: %v", s)
	}
	errs := errorsOf(is)
	if len(errs) != 2 || !strings.Contains(errs[0], "confRev is required for a GOOSE control block") || !strings.Contains(errs[1], "confRev is required for a sampled value control block") {
		t.Errorf("Annex D errors: %v", errs)
	}
}

// Covers: SIG-IPE-2069
func TestSchemaContentModels(t *testing.T) {
	needSchema(t)
	_, src := official(t, "Annex D - SCL example.scd")
	cases := []struct{ from, to, want string }{
		// a second Header
		{`<Header id="SCL Example T1-1"`, `<Header id="x" uuid="7e5bd21f-4c3c-44f2-9a48-6c1f1f0e3a3b"/><Header id="SCL Example T1-1"`, "SCL has 2 Header elements (at most 1)"},
		// an LDevice without LN0
		{`<LN0 inst="" lnClass="LLN0" lnType="LN0" uuid="ea3f6e08-3abb-481d-a62a-ebfd099a29fb" templateUuid="0dafb60c-4b15-4ee2-8b4e-814d54245bb2"/>`, `<LN inst="1" lnClass="GGIO" lnType="LN0"/>`, "LDevice needs at least 1 LN0"},
		// xs:all (Services): any order (ClientServices first in the example), each at most once
		{"<GetDirectory/>", "<GetDirectory/><GetDirectory/>", "Services has 2 GetDirectory elements (at most 1)"},
	}
	for _, c := range cases {
		if !strings.Contains(src, c.from) {
			t.Fatalf("vector text %q not found", c.from)
		}
		is := validateText(t, strings.Replace(src, c.from, c.to, 1))
		if !is.Has(c.want) {
			t.Errorf("want %q; got %v", c.want, schemaIssues(is))
		}
	}
	// out of order: DataTypeTemplates before IED
	a := strings.Index(src, "\t<DataTypeTemplates>")
	b := strings.Index(src, "</DataTypeTemplates>") + len("</DataTypeTemplates>")
	i := strings.Index(src, "\t<IED ")
	moved := src[:i] + src[a:b] + "\n" + src[i:a] + src[b:]
	if is := validateText(t, moved); !is.Has("IED is out of order in SCL") {
		t.Errorf("order: %v", schemaIssues(is))
	}
}

// Covers: SIG-IPE-2070
func TestSchemaSimpleTypes(t *testing.T) {
	needSchema(t)
	_, src := official(t, "Annex D - SCL example.scd")
	cases := []struct{ from, to, want string }{
		// enumeration
		{`<DO name="Mod" type="myMod"/>`, `<DO name="Mod" type="myMod" transient="yes"/>`, `transient="yes" is not a boolean`},
		// pattern (tLNClass), union member types (tLNInstOrEmpty)
		{`lnClass="CSWI"`, `lnClass="cswi"`, `lnClass="cswi"`},
		// required attribute
		{`<Header id="SCL Example T1-1"`, `<Header`, "required attribute id is missing"},
		// UUID pattern
		{`uuid="`, `uuid="not-a-uuid" x="`, `uuid="not-a-uuid"`},
	}
	for _, c := range cases {
		if !strings.Contains(src, c.from) {
			t.Fatalf("vector text %q not found", c.from)
		}
		is := validateText(t, strings.Replace(src, c.from, c.to, 1))
		if !is.Has(c.want) {
			t.Errorf("want %q; got %v", c.want, errorsOf(is))
		}
	}
	// facet checks on their own
	r := &xsdRun{s: schema()}
	for _, c := range []struct{ typ, v, want string }{
		{"xs:boolean", "true", ""}, {"xs:boolean", "yes", "is not a boolean"},
		{"xs:unsignedInt", "4294967296", "is out of range"}, {"xs:unsignedByte", "255", ""},
		{"tSclRelease", "0", "must be more than 0"}, {"tSclRelease", "5", ""},
		{"tRightEnum", "fix", ""}, {"tRightEnum", "full-ish", "is not one of"},
		{"tIEDNameOrRelative", "@", ""}, {"tIEDNameOrRelative", "E1Q1SB1", ""},
		{"tUnitMultiplierEnum", "k", ""}, {"tUnitMultiplierEnum", "kk", "is not a value of tUnitMultiplierEnum"},
		{"tPTypeEnum", "APPID", ""}, {"tPTypeEnum", "VendorX-Thing", ""}, {"tPTypeEnum", "vendor", "is not a valid"},
		{"tUUIDAttribute", "a0e0e1f7-4a2e-4d6f-9f64-5f5c1f1f3a3b", ""},
	} {
		if _, ok := r.s.simple[c.typ]; !ok && !strings.HasPrefix(c.typ, "xs:") {
			t.Errorf("no simple type %s", c.typ)
			continue
		}
		got := r.simpleValue(c.typ, c.v)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s %q: %q, want %q", c.typ, c.v, got, c.want)
		}
	}
}

// Covers: SIG-IPE-2071
func TestSchemaIdentityConstraints(t *testing.T) {
	needSchema(t)
	_, src := official(t, "Annex D - SCL example.scd")
	cases := []struct{ from, to, want string }{
		// keyref: an LN's lnType must name an LNodeType of its class
		{`lnType="CSWIa"`, `lnType="CSWIz"`, "refers to CSWIz/CSWI which is not defined (ref2LNodeTypeDomain2)"},
		// key: two IEDs of one name
		{`<IED name="E1Q1SB1"`, `<IED name="D1Q1SB4"`, "IED duplicates D1Q1SB4"},
		// unique: two DOTypes of one id
		{`<DOType id="myMod"`, `<DOType id="myPos"`, "DOType duplicates myPos"},
	}
	for _, c := range cases {
		if !strings.Contains(src, c.from) {
			t.Fatalf("vector text %q not found", c.from)
		}
		is := validateText(t, strings.Replace(src, c.from, c.to, 1))
		if !is.Has(c.want) {
			t.Errorf("want %q; got %v", c.want, schemaIssues(is))
		}
	}
}

// Covers: SIG-IPE-2073
func TestSchemaVersionsAndExtensions(t *testing.T) {
	needSchema(t)
	_, src := official(t, "Annex D - SCL example.scd")
	// A 2007B4 document is checked against 2007C5 with the structural
	// departures as warnings (Header uuid became required in C5).
	old := strings.Replace(src, `revision="C" release="5"`, `revision="B" release="4"`, 1)
	old = strings.Replace(old, `<Header id="SCL Example T1-1"`, `<Header id="SCL Example T1-1" x=""`, 1)
	d, err := Parse([]byte(old))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(src, `revision="C" release="5"`) {
		is := Validate(d, Options{})
		for _, i := range is.Errors() {
			if i.Clause == "XSD" {
				t.Errorf("2007B4 structural departure reported as error: %s", i)
			}
		}
	}
	// 8.2.1 on top of the XSD: unknown elements are ignored with a warning,
	// unknown attributes too; foreign-namespace attributes are allowed.
	is := validateText(t, strings.Replace(src, `<Substation name="S12"`, `<Substation xmlns:e="urn:x" e:note="kept" name="S12"`, 1))
	if s := schemaIssues(is); len(s) != 0 {
		t.Errorf("foreign attribute: %v", s)
	}
	// tHeader has no anyAttribute
	is = validateText(t, strings.Replace(src, `<Header id="SCL Example T1-1"`, `<Header xmlns:e="urn:x" e:note="kept" id="SCL Example T1-1"`, 1))
	if !is.Has("attribute e:note of another namespace is not allowed on Header") {
		t.Errorf("foreign attribute on Header: %v", schemaIssues(is))
	}
	is = validateText(t, strings.Replace(src, `<Substation name="S12"`, `<Substation someday="1" name="S12"`, 1))
	if !is.Has("attribute someday is not defined for Substation and is ignored") || len(schemaIssues(is)) != 0 {
		t.Errorf("unknown attribute: %v", is)
	}
	// The ASD examples of IEC TR 61850-7-6 (6-100 extension in Private)
	// are valid by the schema.
	for _, f := range []string{"Reverse Blocking_0_1.asd", "Line distance protection_0_1.asd"} {
		raw, err := os.ReadFile(filepath.Join(codeComponent(t), "..", "IEC_61850-7-6.ASD.2024A2", f))
		if err != nil {
			t.Fatal(err)
		}
		d, err := Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if s := schemaIssues(Validate(d, Options{})); len(s) != 0 {
			t.Errorf("%s: %v", f, s)
		}
	}
}

// Lenient validation (the IEC 61850 IPE's default, sclValidation warn):
// the departures engineering tools commonly make are accepted warnings,
// each still an error in the strict (default Options) reading; structural
// errors (a dangling lnType, a type referenced but not defined, an unknown
// mustUnderstand element) stay errors. A document declared in another
// encoding (ISO-8859-1) is converted with a warning (8.4).
// Covers: SIG-IPE-3519
func TestLenientVendorDeviations(t *testing.T) {
	needSchema(t)
	_, src := official(t, "Annex D - SCL example.scd")
	deviations := []struct{ name, from, to string }{
		{"schema version 2007B4 without Header uuid", `revision="C" release="5"`, `revision="B" release="4"`},
		{"vendor namespace element after SCL elements", `</Substation>`, `<v:Extra xmlns:v="urn:vendor"/></Substation>`},
		{"foreign attribute on Header", `<Header id="SCL Example T1-1"`, `<Header xmlns:e="urn:x" e:note="kept" id="SCL Example T1-1"`},
		{"enum value outside the XSD", `<DO name="Mod" type="myMod"/>`, `<DO name="Mod" type="myMod" transient="yes"/>`},
		{"missing required attribute", `<Header id="SCL Example T1-1"`, `<Header`},
		{"second Header", `<Header id="SCL Example T1-1"`, `<Header id="x" uuid="7e5bd21f-4c3c-44f2-9a48-6c1f1f0e3a3b"/><Header id="SCL Example T1-1"`},
		{"confRev missing (Annex D itself)", "", ""},
	}
	for _, c := range deviations {
		doc := src
		if c.from != "" {
			if !strings.Contains(src, c.from) {
				t.Fatalf("%s: vector text %q not found", c.name, c.from)
			}
			doc = strings.Replace(src, c.from, c.to, 1)
		}
		d, err := Parse([]byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		// (2007B4 is already a warning in the strict reading, F-1163.)
		if c.from != "" && !strings.HasPrefix(c.name, "schema version") && len(Validate(d, Options{}).Errors()) <= 2 {
			t.Errorf("%s: not an error in the strict reading", c.name)
		}
		is := Validate(d, Options{Lenient: true})
		if e := is.Errors(); len(e) != 0 {
			t.Errorf("%s: lenient errors %v", c.name, e)
		}
		accepted := 0
		for _, i := range is {
			if i.Accepted {
				accepted++
			}
		}
		if accepted == 0 {
			t.Errorf("%s: no accepted warning in %v", c.name, is)
		}
	}
	// Element order: DataTypeTemplates before IED.
	a := strings.Index(src, "\t<DataTypeTemplates>")
	b := strings.Index(src, "</DataTypeTemplates>") + len("</DataTypeTemplates>")
	i := strings.Index(src, "\t<IED ")
	d, err := Parse([]byte(src[:i] + src[a:b] + "\n" + src[i:a] + src[b:]))
	if err != nil {
		t.Fatal(err)
	}
	if e := Validate(d, Options{Lenient: true}).Errors(); len(e) != 0 {
		t.Errorf("element order: lenient errors %v", e)
	}
	// Structural: kept as errors.
	for _, c := range []struct{ from, to, want string }{
		{`lnType="CSWIa"`, `lnType="CSWIz"`, "is not defined in DataTypeTemplates"},
		{`<DO name="Mod" type="myMod"/>`, `<DO name="Mod" type="noSuchType"/>`, "which is not defined"},
	} {
		d, err := Parse([]byte(strings.Replace(src, c.from, c.to, 1)))
		if err != nil {
			t.Fatal(err)
		}
		e := Validate(d, Options{Lenient: true}).Errors()
		if !e.Has(c.want) || !e[0].Structural {
			t.Errorf("structural %q: lenient errors %v", c.want, e)
		}
	}
	// ISO-8859-1.
	latin := strings.Replace(src, `encoding="UTF-8"`, `encoding="ISO-8859-1"`, 1)
	if latin == src {
		t.Fatal("no UTF-8 declaration in the example")
	}
	latin = strings.Replace(latin, `<Substation name="S12"`, "<Substation desc=\"Sch\xf6nau\" name=\"S12\"", 1)
	d, err = Parse([]byte(latin))
	if err != nil {
		t.Fatalf("ISO-8859-1: %v", err)
	}
	if n := findLocal(d.Tree.Root, "Substation"); n == nil || n.A("desc") != "Schönau" {
		t.Errorf("ISO-8859-1 text not converted")
	}
	if is := Validate(d, Options{Lenient: true}); !is.Has("encoded in ISO-8859-1") || len(is.Errors()) != 0 {
		t.Errorf("ISO-8859-1: %v", is)
	}
}
