package model

import (
	"fmt"
	"io/fs"
	"strings"
)

// The raw NSD tables, read from IEC's NSD, SNSD and ASD files at run time
// (nsdfiles.go: LoadNSD, SetNSDJSON). build turns them into the Model;
// data/text.yaml adds what the "Light" NSD edition has only as references
// (meanings) and the 7-2 packed types, SetDescriptions the LN class titles
// and abbreviation meanings.

type nsdDoc struct {
	ID, Version, Revision, Release, File string
}

type nsdFC struct {
	Name           string
	Services       []string
	DataSetMembers []string
	Source         string
}

type nsdPresCond struct {
	Name, Argument, Source string
}

type nsdEnum struct {
	Name, Source string
	Items        []nsdLiteral
}

type nsdLiteral struct {
	Name       string
	Value      int
	Deprecated bool
}

type nsdAttr struct {
	Kind                           string
	Name, Type, TypeKind           string
	UnderlyingType, UnderlyingKind string
	FC                             string
	Dchg, Qchg, Dupd               bool
	PresCond, PresCondArgs         string
	DefaultValue                   string
	MinValue, MaxValue             string
	IsArray                        bool
	SizeAttribute, MaxIndexAttr    string
	Deprecated                     bool
}

type nsdCA struct {
	Name, Source          string
	TypeKindParameterized bool
	Attrs                 []nsdAttr
}

type nsdCDC struct {
	Name, Variant         string
	Statistics            bool
	EnumParameterized     bool
	TypeKindParameterized bool
	Attrs                 []nsdAttr
}

type nsdDO struct {
	Name, Type                     string
	UnderlyingType, UnderlyingKind string
	Transient                      bool
	PresCond, PresCondArgs         string
	DsPresCond, DsPresCondArgs     string
	Deprecated                     bool
}

type nsdLN struct {
	Name, Base string
	Abstract   bool
	CanHaveLOG bool
	DOs        []nsdDO
}

type nsdServiceCDC struct {
	CDC   string
	Attrs []nsdAttr
}

type nsdRealization struct {
	Name, Realize string
	Attrs         []nsdAttr
}

type nsdAppliesTo struct {
	Service, ID, Version, Revision string
	Release                        int
}

type nsdTables struct {
	Docs          []nsdDoc
	BasicTypes    []string
	FCs           []nsdFC
	PresConds     []nsdPresCond
	Enums         []nsdEnum
	CAs           []nsdCA
	CDCs          []nsdCDC
	Abbreviations []string
	LNs           []nsdLN
	ServiceCAs    []nsdCA
	ServiceCDCs   []nsdServiceCDC
	Realizations  []nsdRealization
	ServiceAppNS  []nsdAppliesTo
	ASDs          []asdFile
}

type asdFile struct {
	File, HeaderID, UUID string
	Applications         []asdApp
	Functions            []asdFunction
	LNodeTypes           []asdLNodeType
	DOTypes              []asdDOType
}

type asdApp struct {
	Name  string
	Roles []asdRole
}

type asdRole struct {
	Name      string
	Functions []string
	Signals   []asdSignal
}

type asdSignal struct {
	Function, Name string
	Inputs         []string
}

type asdFunction struct {
	Path   string
	LNodes []asdLNode
}

type asdLNode struct {
	Prefix, LNClass, LNInst, LNType string
	Inputs                          []asdInput
}

type asdInput struct {
	Service, Input, InputInst, PLN, PDO, PDA, Source, Resource string
}

type asdLNodeType struct {
	ID, LNClass string
	DOs         []asdDO
}

type asdDO struct{ Name, Type string }

type asdDOType struct {
	ID, CDC string
	DAs     []asdDA
}

type asdDA struct{ Name, FC, BType, Type string }

// textFile is data/text.yaml.
type textFile struct {
	FunctionalConstraints      map[string]string   `yaml:"functionalConstraints"`
	ExtraFunctionalConstraints []string            `yaml:"extraFunctionalConstraints"`
	PresenceConditions         map[string]string   `yaml:"presenceConditions"`
	Groups                     map[string]string   `yaml:"groups"`
	CDCKinds                   map[string][]string `yaml:"cdcKinds"`
	TypeNames                  map[string]string   `yaml:"typeNames"`
	BasicTypes                 []string            `yaml:"basicTypes"`
	Types72                    []AttrType          `yaml:"types72"`
	Enums72                    []Enum              `yaml:"enums72"`
	LNTitles                   map[string]string   `yaml:"lnTitles"`
	Abbreviations              map[string]string   `yaml:"abbreviations"`
}

// Versions names the NSD files the model is generated from
// ("IEC 61850-7-3:2007B6" …).
func (m *Model) Versions() []string {
	var out []string
	for _, d := range nsdTablesOf().Docs {
		out = append(out, fmt.Sprintf("%s:%s%s%s", d.ID, d.Version, d.Revision, d.Release))
	}
	return out
}

// sectionOf maps a CDC kind to the LN table section its data objects are
// listed under.
var sectionOf = map[string]string{
	"description": "descriptions", "status": "status", "serviceTracking": "status", "measurand": "measured",
	"controllable": "controls", "statusSetting": "settings", "analogueSetting": "settings",
}

// build fills m from the generated tables and data/text.yaml.
func (m *Model) build(tf *textFile) error {
	var errs []string
	fail := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	tn := func(t string) string {
		if n, ok := tf.TypeNames[t]; ok {
			return n
		}
		return t
	}
	// Functional constraints: 7-2 and the 8-1 CO, plus the control block FCs.
	for _, f := range nsdTablesOf().FCs {
		mean, ok := tf.FunctionalConstraints[f.Name]
		if !ok {
			fail("text.yaml: no meaning for FC %s", f.Name)
		}
		m.FCs[f.Name] = mean
		m.FCServices[f.Name] = f.Services
	}
	for _, f := range tf.ExtraFunctionalConstraints {
		if _, dup := m.FCs[f]; dup {
			fail("text.yaml: extra FC %s is in the NSD", f)
		}
		m.FCs[f] = tf.FunctionalConstraints[f]
	}
	for k := range tf.FunctionalConstraints {
		if _, ok := m.FCs[k]; !ok {
			fail("text.yaml: FC %s is not in the NSD nor listed as extra", k)
		}
	}
	// Presence conditions (7-2 and 8-1).
	for _, p := range nsdTablesOf().PresConds {
		mean, ok := tf.PresenceConditions[p.Name]
		if !ok {
			fail("text.yaml: no meaning for presence condition %s", p.Name)
		}
		code := p.Name
		if p.Argument != "" {
			code += "(" + strings.ReplaceAll(p.Argument, " ", "") + ")"
		}
		m.Presence[code] = mean
	}
	for k := range tf.PresenceConditions {
		if m.presenceCode(k) == "" && m.presenceCode(k+"(x)") == "" {
			fail("text.yaml: presence condition %s is not in the NSD", k)
		}
	}
	for _, t := range nsdTablesOf().BasicTypes {
		m.BasicTypes[tn(t)] = true
	}
	for _, t := range tf.BasicTypes {
		m.BasicTypes[t] = true
	}
	// Enumerations.
	for _, e := range nsdTablesOf().Enums {
		en := &Enum{Name: e.Name, Source: e.Source}
		for _, it := range e.Items {
			en.Items = append(en.Items, EnumItem{Name: it.Name, Value: it.Value, Deprecated: it.Deprecated})
		}
		if _, dup := m.Enums[en.Name]; dup {
			fail("duplicate enumeration %s", en.Name)
		}
		m.Enums[en.Name] = en
	}
	for i := range tf.Enums72 {
		e := tf.Enums72[i]
		if _, dup := m.Enums[e.Name]; dup {
			fail("text.yaml: enumeration %s is in the NSD", e.Name)
		}
		m.Enums[e.Name] = &e
	}
	// Constructed attribute classes (7-2 Originator, 7-3 Clause 6) and the 7-2 packed types.
	for i := range tf.Types72 {
		t := tf.Types72[i]
		m.AttrTypes[t.Name] = &t
	}
	for _, c := range nsdTablesOf().CAs {
		at := &AttrType{Name: c.Name, Source: c.Source}
		for _, a := range c.Attrs {
			at.Attrs = append(at.Attrs, convAttr(a, tn))
		}
		if _, dup := m.AttrTypes[at.Name]; dup {
			fail("duplicate constructed attribute %s", at.Name)
		}
		m.AttrTypes[at.Name] = at
	}
	// Common data classes; a setting class comes as one CDC per variant.
	kind := map[string]string{}
	for k, names := range tf.CDCKinds {
		for _, n := range names {
			kind[n] = k
		}
	}
	variants := map[string][]*CDC{}
	var baseOrder []string
	for _, c := range nsdTablesOf().CDCs {
		k, ok := kind[c.Name]
		if !ok {
			fail("text.yaml: CDC %s has no kind", c.Name)
		}
		cdc := &CDC{Name: c.Name, Kind: k}
		for _, a := range c.Attrs {
			cdc.Attrs = append(cdc.Attrs, convAttr(a, tn))
		}
		if c.Variant == "" {
			m.CDCs[cdc.Name] = cdc
			m.cdcOrder = append(m.cdcOrder, cdc.Name)
			continue
		}
		cdc.Name, cdc.VariantOf, cdc.FC = c.Name+"_"+c.Variant, c.Name, c.Variant
		if len(variants[c.Name]) == 0 {
			baseOrder = append(baseOrder, c.Name)
			m.cdcOrder = append(m.cdcOrder, c.Name)
		}
		variants[c.Name] = append(variants[c.Name], cdc)
		m.CDCs[cdc.Name] = cdc
		m.cdcOrder = append(m.cdcOrder, cdc.Name)
	}
	for _, b := range baseOrder {
		// The abstract base carries what every variant has (d, dU, cdcName, dataNs …).
		vs := variants[b]
		base := &CDC{Name: b, Kind: vs[0].Kind, Abstract: true}
		for _, a := range vs[0].Attrs {
			common := true
			for _, v := range vs[1:] {
				va, ok := v.Attr(a.Name)
				if !ok || va.FC != a.FC || va.Type != a.Type {
					common = false
				}
			}
			if common {
				base.Attrs = append(base.Attrs, a)
			}
		}
		m.CDCs[b] = base
	}
	for n := range kind {
		if _, ok := m.CDCs[n]; !ok {
			fail("text.yaml: kind for CDC %s which is not in the NSD", n)
		}
	}
	// Logical node classes with the data objects of their base classes.
	raw := map[string]*nsdLN{}
	for i := range nsdTablesOf().LNs {
		raw[nsdTablesOf().LNs[i].Name] = &nsdTablesOf().LNs[i]
	}
	for _, l := range nsdTablesOf().LNs {
		chain := []*nsdLN{}
		for c := &l; c != nil; {
			chain = append([]*nsdLN{c}, chain...)
			if c.Base == "" {
				break
			}
			b, ok := raw[c.Base]
			if !ok {
				fail("LN %s: unknown base %s", c.Name, c.Base)
				break
			}
			c = b
		}
		cls := &LNClass{Name: l.Name, Abstract: l.Abstract, Title: tf.LNTitles[l.Name]}
		if !l.Abstract {
			cls.Group = l.Name[:1]
		}
		byName := map[string]int{}
		var dos []DataObject
		// Most derived class first, as the 7-4 tables list them; a class
		// restating a data object of its base wins.
		for ci := len(chain) - 1; ci >= 0; ci-- {
			c := chain[ci]
			for _, d := range c.DOs {
				do := convDO(d, tn)
				if c.Name != l.Name {
					do.InheritedFrom = c.Name
				}
				if ck, ok := kind[strings.SplitN(do.CDC, "_", 2)[0]]; ok {
					do.Section = sectionOf[ck]
				}
				if _, ok := byName[d.Name]; ok {
					continue
				}
				byName[d.Name] = len(dos)
				dos = append(dos, do)
			}
		}
		for _, sec := range []string{"descriptions", "status", "measured", "controls", "settings", ""} {
			for _, d := range dos {
				if d.Section == sec {
					cls.DataObjects = append(cls.DataObjects, d)
				}
			}
		}
		if _, dup := m.LNs[cls.Name]; dup {
			fail("duplicate LN class %s", cls.Name)
		}
		m.LNs[cls.Name] = cls
		m.lnOrder = append(m.lnOrder, cls.Name)
	}
	for n := range tf.LNTitles {
		if _, ok := m.LNs[n]; !ok {
			fail("text.yaml: title for LN class %s which is not in the NSD", n)
		}
	}
	for g, mean := range tf.Groups {
		m.Groups[g] = mean
	}
	nsdAbbr := map[string]bool{}
	for _, a := range nsdTablesOf().Abbreviations {
		nsdAbbr[a] = true
	}
	for t, mean := range tf.Abbreviations {
		if !nsdAbbr[t] {
			fail("text.yaml: abbreviation %s is not in the 7-4 NSD", t)
		}
		m.Abbrev[t] = mean
	}
	m.AbbrevNames = append([]string(nil), nsdTablesOf().Abbreviations...)
	// IEC 61850-8-1 service CDCs: the controllable classes.
	for _, s := range nsdTablesOf().ServiceCDCs {
		m.controllable[s.CDC] = true
		for _, a := range s.Attrs {
			m.ServiceAttrs[s.CDC] = append(m.ServiceAttrs[s.CDC], convAttr(a, tn))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("model tables: %s", strings.Join(errs, "; "))
	}
	return nil
}

// presence renders an NSD presence condition with its arguments as the
// model writes it ("AtLeastOne(1)", "OmultiRange(33,48)").
func presence(cond, args string) string {
	if args == "" {
		return cond
	}
	return cond + "(" + strings.ReplaceAll(args, " ", "") + ")"
}

func convAttr(a nsdAttr, tn func(string) string) Attr {
	out := Attr{Name: a.Name, Type: tn(a.Type), FC: a.FC, Array: a.IsArray, Presence: presence(a.PresCond, a.PresCondArgs), Default: a.DefaultValue}
	if a.SizeAttribute != "" {
		out.MaxIndex = a.SizeAttribute + "-1"
	}
	if a.MaxIndexAttr != "" {
		out.MaxIndex = a.MaxIndexAttr
	}
	if out.Type == "" {
		switch a.TypeKind {
		case "ENUMERATED":
			out.Type = "EnumDA"
		default:
			out.Type = "DA"
		}
	}
	if a.MinValue != "" || a.MaxValue != "" {
		out.Range = "[" + a.MinValue + "..." + a.MaxValue + "]"
	}
	if a.Dchg {
		out.TrgOp = append(out.TrgOp, "dchg")
	}
	if a.Qchg {
		out.TrgOp = append(out.TrgOp, "qchg")
	}
	if a.Dupd {
		out.TrgOp = append(out.TrgOp, "dupd")
	}
	out.SubDataObject = a.Kind == "SubDataObject"
	out.ServiceParameter = a.Kind == "ServiceParameter"
	return out
}

func convDO(d nsdDO, tn func(string) string) DataObject {
	do := DataObject{Name: d.Name, CDC: d.Type, Transient: d.Transient,
		Pres: presence(d.PresCond, d.PresCondArgs), PresDs: presence(d.DsPresCond, d.DsPresCondArgs)}
	switch d.Type {
	case "ENS", "ENC", "ENG":
		do.Enum = d.UnderlyingType
	default:
		if d.UnderlyingType != "" {
			do.CtlValType = tn(d.UnderlyingType)
		}
	}
	return do
}

// loadText reads data/text.yaml.
func loadText(fsys fs.FS) (*textFile, error) {
	var tf textFile
	if err := readYAML(fsys, "data/text.yaml", &tf); err != nil {
		return nil, err
	}
	return &tf, nil
}
