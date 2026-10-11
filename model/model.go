// Package model is the IEC 61850 data model as data: the common data
// classes and constructed attribute classes of IEC 61850-7-3, the logical
// node classes of IEC 61850-7-4 with their data objects, the enumerations
// of 7-2, 7-3 and 7-4, the functional constraints and presence conditions
// of 7-2 and the control services of IEC 61850-8-1 they use.
//
// The tables are read at run time from IEC's machine-readable name space
// definitions (NSD files of IEC 61850-7-2/-7-3/-7-4 2007B6 and the
// IEC 61850-8-1 SNSD 2003A4 when this was written), which IEC publishes
// under its own licence and this module does not carry: an application
// loads them with LoadNSD (or SetNSDJSON), and until then Default returns
// ErrNoNSD. Nothing of them is typed into Go code. data/text.yaml adds
// what the NSD "Light" edition holds only as references (meanings) and
// the 7-2 packed types (Quality, Timestamp) the NSD leaves as basic
// types; LN titles and abbreviation meanings come from SetDescriptions.
// The package answers the
// questions a client and an SCL import ask: what a common data class or
// logical node class contains, whether an object reference (LD/LN.DO.DA
// with its functional constraint) exists in the model, what a data object
// means in plain words and which unit it carries, which data objects a
// class requires and which control model a controllable class supports.
// It also checks a device model against a Basic Application Profile of
// IEC TR 61850-7-6 Ed. 2.0 (bap.go), whose application templates come from
// the IEC TR 61850-7-6 ASD machine-readable file (2024A2).
package model

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed data/*.yaml
var dataFS embed.FS

// Attr is a data attribute of a common data class, or a member of a
// constructed attribute class.
type Attr struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Array    bool     `yaml:"array"`
	MaxIndex string   `yaml:"maxIndex"`
	FC       string   `yaml:"fc"`
	TrgOp    []string `yaml:"trgOp"`
	Presence string   `yaml:"presence"`
	Range    string   `yaml:"range"`
	Default  string   `yaml:"default"`
	// SubDataObject is set when Type is a common data class (WYE.phsA).
	SubDataObject bool `yaml:"subDataObject"`
	// ServiceParameter marks ctlVal: a parameter of the control services,
	// not an attribute read from the server.
	ServiceParameter bool   `yaml:"serviceParameter"`
	InheritedFrom    string `yaml:"inheritedFrom"`
	// Bits gives the bit positions of a packed 7-2 type member.
	Bits string `yaml:"bits"`
}

// CDC is a common data class of IEC 61850-7-3.
type CDC struct {
	Name     string `yaml:"name"`
	Clause   string `yaml:"clause"`
	Table    int    `yaml:"table"`
	Kind     string `yaml:"kind"` // status, measurand, controllable, statusSetting, analogueSetting, description, serviceTracking, abstract
	Abstract bool   `yaml:"abstract"`
	// VariantOf names the setting class a per-FC class specialises
	// (SPG_SP of SPG); FC is then its setting constraint.
	VariantOf string   `yaml:"variantOf"`
	FC        string   `yaml:"fc"`
	Inherits  []string `yaml:"inherits"`
	Attrs     []Attr   `yaml:"attrs"`
}

// Attr returns the named attribute.
func (c *CDC) Attr(name string) (*Attr, bool) {
	for i := range c.Attrs {
		if c.Attrs[i].Name == name {
			return &c.Attrs[i], true
		}
	}
	return nil, false
}

// AttrType is a constructed attribute class of IEC 61850-7-3 Clause 6 or a
// type of IEC 61850-7-2 used by the classes.
type AttrType struct {
	Name   string `yaml:"name"`
	Clause string `yaml:"clause"`
	Table  int    `yaml:"table"`
	Source string `yaml:"source"`
	Packed string `yaml:"packed"`
	Attrs  []Attr `yaml:"attrs"`
}

// EnumItem is one literal of an enumeration.
type EnumItem struct {
	Name       string `yaml:"name"`
	Value      int    `yaml:"value"`
	Deprecated bool   `yaml:"deprecated"`
}

// Enum is an enumeration of 7-2, 7-3 or 7-4.
type Enum struct {
	Name   string     `yaml:"name"`
	Source string     `yaml:"source"`
	Clause string     `yaml:"clause"`
	Table  int        `yaml:"table"`
	Page   int        `yaml:"page"`
	Items  []EnumItem `yaml:"items"`
}

// Literal returns the literal of value v.
func (e *Enum) Literal(v int) (string, bool) {
	for _, it := range e.Items {
		if it.Value == v {
			return it.Name, true
		}
	}
	return "", false
}

// Value returns the value of literal name (exact match first, then
// ignoring case).
func (e *Enum) Value(name string) (int, bool) {
	for _, it := range e.Items {
		if it.Name == name {
			return it.Value, true
		}
	}
	for _, it := range e.Items {
		if strings.EqualFold(it.Name, name) {
			return it.Value, true
		}
	}
	return 0, false
}

// DataObject is a data object of a logical node class.
type DataObject struct {
	Name string `yaml:"name"`
	CDC  string `yaml:"cdc"`
	// Enum is the enumeration of an ENS, ENC or ENG data object.
	Enum string `yaml:"enum"`
	// CtlValType is the ctlVal type of a CTS tracking object (LTRK).
	CtlValType string `yaml:"ctlValType"`
	Transient  bool   `yaml:"transient"`
	// Pres and PresDs are the presence conditions for non-derived and
	// derived statistics.
	Pres          string `yaml:"pres"`
	PresDs        string `yaml:"presDs"`
	Section       string `yaml:"section"` // descriptions, status, measured, controls, settings
	InheritedFrom string `yaml:"inheritedFrom"`
}

// Multi reports whether the data object may be instantiated with an
// instance number (Ind1, Ind2 …).
func (d *DataObject) Multi() bool {
	return strings.HasPrefix(d.Pres, "Omulti") || strings.HasPrefix(d.Pres, "Mmulti")
}

// Mandatory reports whether the data object is mandatory without
// condition (M) for non-derived statistics, or for derived statistics
// with ds.
func (d *DataObject) Mandatory(ds bool) bool {
	p := d.Pres
	if ds {
		p = d.PresDs
	}
	return p == "M" || strings.HasPrefix(p, "Mmulti")
}

// LNClass is a logical node class of IEC 61850-7-4 (abstract classes
// included).
type LNClass struct {
	Name        string       `yaml:"name"`
	Table       int          `yaml:"table"`
	Clause      string       `yaml:"clause"`
	Title       string       `yaml:"title"`
	Abstract    bool         `yaml:"abstract"`
	Group       string       `yaml:"group"`
	DataObjects []DataObject `yaml:"dataObjects"`
}

// DataObject returns the named data object; a name with an instance
// number (Ind3, RxPrm1) matches a multi-instance data object.
func (l *LNClass) DataObject(name string) (*DataObject, bool) {
	for i := range l.DataObjects {
		if l.DataObjects[i].Name == name {
			return &l.DataObjects[i], true
		}
	}
	base := strings.TrimRight(name, "0123456789")
	if base != name && base != "" {
		for i := range l.DataObjects {
			if l.DataObjects[i].Name == base && l.DataObjects[i].Multi() {
				return &l.DataObjects[i], true
			}
		}
	}
	return nil, false
}

// Model holds the loaded tables.
type Model struct {
	CDCs      map[string]*CDC
	AttrTypes map[string]*AttrType
	Enums     map[string]*Enum
	LNs       map[string]*LNClass
	// Groups maps an LN group letter to its meaning.
	Groups map[string]string
	// FCs maps a functional constraint to its meaning.
	FCs map[string]string
	// Presence maps a presence condition code to its meaning.
	Presence map[string]string
	// BasicTypes are the 7-2 basic and common types attributes may have.
	BasicTypes map[string]bool
	// Abbrev maps 7-4 abbreviations to their first meaning (where known);
	// AbbrevNames lists every abbreviation of the 7-4 NSD.
	Abbrev      map[string]string
	AbbrevNames []string
	// FCServices lists the services applicable to each functional
	// constraint (7-2 NSD; CO from the 8-1 SNSD).
	FCServices map[string][]string
	// ServiceAttrs are the IEC 61850-8-1 service data attributes of the
	// controllable classes (SBOw, Oper, Cancel under CO; 8-1 SNSD).
	ServiceAttrs map[string][]Attr
	BAPs         map[string]*BAP

	cdcOrder, lnOrder []string
	controllable      map[string]bool
	text              *textFile
}

var (
	defMu sync.Mutex
	defM  *Model

	descMu   sync.RWMutex
	descLN   map[string]string
	descAbbr map[string]string
)

// Default returns the model built from the loaded name space definitions
// (LoadNSD or SetNSDJSON) and the embedded supplement. Before the name
// space definitions are loaded it returns ErrNoNSD. The model is built
// once and rebuilt after a new LoadNSD, SetNSDJSON or SetDescriptions.
func Default() (*Model, error) {
	defMu.Lock()
	defer defMu.Unlock()
	if defM != nil {
		return defM, nil
	}
	m, err := Load(dataFS)
	if err != nil {
		return nil, err
	}
	defM = m
	return m, nil
}

// SetDescriptions gives the model the titles of the logical node classes
// (LNClass.Title) and the meanings of the IEC 61850-7-4 abbreviations
// (Model.Abbrev), which Describe composes descriptions from. They come
// from the text of IEC 61850-7-4, which this module does not carry; without
// them titles are empty and descriptions use the names. Every key must be
// a class or abbreviation of the loaded name space definitions, or the
// model does not build.
func SetDescriptions(lnTitles, abbreviations map[string]string) {
	descMu.Lock()
	descLN, descAbbr = copyMap(lnTitles), copyMap(abbreviations)
	descMu.Unlock()
	defMu.Lock()
	defM = nil
	defMu.Unlock()
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// mergeDescriptions adds the titles and abbreviations of SetDescriptions
// to a supplement that does not give them itself.
func mergeDescriptions(tf *textFile) {
	descMu.RLock()
	defer descMu.RUnlock()
	if tf.LNTitles == nil {
		tf.LNTitles = map[string]string{}
	}
	if tf.Abbreviations == nil {
		tf.Abbreviations = map[string]string{}
	}
	for k, v := range descLN {
		if _, ok := tf.LNTitles[k]; !ok {
			tf.LNTitles[k] = v
		}
	}
	for k, v := range descAbbr {
		if _, ok := tf.Abbreviations[k]; !ok {
			tf.Abbreviations[k] = v
		}
	}
}

// Must returns the default model and panics if it cannot be built (no
// name space definitions loaded, or broken ones).
func Must() *Model {
	m, err := Default()
	if err != nil {
		panic(err)
	}
	return m
}

func readYAML(fsys fs.FS, name string, v any) error {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// Load builds the model from the loaded name space definitions (LoadNSD
// or SetNSDJSON) and the supplement data/text.yaml and profiles
// data/bap.yaml read from fsys, and checks every cross reference. It
// returns ErrNoNSD before the name space definitions are loaded.
func Load(fsys fs.FS) (*Model, error) {
	if !nsdLoaded() {
		return nil, ErrNoNSD
	}
	m := &Model{CDCs: map[string]*CDC{}, AttrTypes: map[string]*AttrType{}, Enums: map[string]*Enum{}, LNs: map[string]*LNClass{},
		Groups: map[string]string{}, FCs: map[string]string{}, Presence: map[string]string{}, BasicTypes: map[string]bool{}, Abbrev: map[string]string{},
		FCServices: map[string][]string{}, ServiceAttrs: map[string][]Attr{}, BAPs: map[string]*BAP{}, controllable: map[string]bool{}}
	tf, err := loadText(fsys)
	if err != nil {
		return nil, err
	}
	mergeDescriptions(tf)
	m.text = tf
	if err := m.build(tf); err != nil {
		return nil, err
	}
	var bf struct {
		BAPs []BAP `yaml:"baps"`
	}
	if err := readYAML(fsys, "data/bap.yaml", &bf); err != nil {
		return nil, err
	}
	for i := range bf.BAPs {
		b := bf.BAPs[i]
		m.BAPs[b.Name] = &b
	}
	if err := m.attachTemplates(); err != nil {
		return nil, err
	}
	if err := m.check(); err != nil {
		return nil, err
	}
	return m, nil
}

// knownType reports whether t names a basic type, constructed type,
// enumeration or common data class.
func (m *Model) knownType(t string) bool {
	if m.BasicTypes[t] {
		return true
	}
	if _, ok := m.AttrTypes[t]; ok {
		return true
	}
	if _, ok := m.Enums[t]; ok {
		return true
	}
	_, ok := m.CDCs[t]
	return ok
}

// check verifies every cross reference of the tables.
func (m *Model) check() error {
	var errs []string
	for _, n := range m.cdcOrder {
		c := m.CDCs[n]
		for _, a := range c.Attrs {
			if !m.knownType(a.Type) {
				errs = append(errs, fmt.Sprintf("%s.%s: unknown type %q", n, a.Name, a.Type))
			}
			if a.FC != "" {
				if _, ok := m.FCs[a.FC]; !ok {
					errs = append(errs, fmt.Sprintf("%s.%s: unknown FC %q", n, a.Name, a.FC))
				}
			}
			if a.Presence != "" && m.presenceCode(a.Presence) == "" {
				errs = append(errs, fmt.Sprintf("%s.%s: unknown presence %q", n, a.Name, a.Presence))
			}
		}
		if c.VariantOf != "" {
			if _, ok := m.CDCs[c.VariantOf]; !ok {
				errs = append(errs, fmt.Sprintf("%s: unknown base %s", n, c.VariantOf))
			}
		}
	}
	for _, t := range m.AttrTypes {
		for _, a := range t.Attrs {
			if !m.knownType(a.Type) {
				errs = append(errs, fmt.Sprintf("%s.%s: unknown type %q", t.Name, a.Name, a.Type))
			}
		}
	}
	for _, n := range m.lnOrder {
		l := m.LNs[n]
		for _, d := range l.DataObjects {
			if _, ok := m.CDCs[d.CDC]; !ok {
				errs = append(errs, fmt.Sprintf("%s.%s: unknown CDC %q", n, d.Name, d.CDC))
			}
			if d.Enum != "" && d.Enum != "EnumDA" {
				if _, ok := m.Enums[d.Enum]; !ok {
					errs = append(errs, fmt.Sprintf("%s.%s: unknown enumeration %q", n, d.Name, d.Enum))
				}
			}
			for _, p := range []string{d.Pres, d.PresDs} {
				if m.presenceCode(p) == "" {
					errs = append(errs, fmt.Sprintf("%s.%s: unknown presence %q", n, d.Name, p))
				}
			}
		}
	}
	for _, b := range m.BAPs {
		for _, e := range b.check(m) {
			errs = append(errs, e.Error())
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("model tables: %s", strings.Join(errs, "; "))
	}
	return nil
}

// presenceCode returns the table code a presence condition instantiates
// (AtLeastOne(2) -> AtLeastOne(n), MO(db) -> MO(sibling)), or "".
func (m *Model) presenceCode(p string) string {
	if _, ok := m.Presence[p]; ok {
		return p
	}
	i := strings.IndexByte(p, '(')
	if i < 0 || !strings.HasSuffix(p, ")") {
		return ""
	}
	head := p[:i]
	for code := range m.Presence {
		if strings.HasPrefix(code, head+"(") {
			return code
		}
	}
	return ""
}

// FindAttr returns the attribute of a class, looking also in the per-FC
// variants of a setting class (ING -> ING_SP.setVal) and in the 8-1
// service data attributes of a controllable class (DPC -> Oper).
func (m *Model) FindAttr(cdc, name string) (*Attr, bool) {
	c, ok := m.CDCs[cdc]
	if !ok {
		return nil, false
	}
	if a, ok := c.Attr(name); ok {
		return a, true
	}
	for _, v := range m.Variants(cdc) {
		if a, ok := v.Attr(name); ok {
			return a, true
		}
	}
	for i := range m.ServiceAttrs[cdc] {
		if a := &m.ServiceAttrs[cdc][i]; a.Name == name {
			return a, true
		}
	}
	return nil, false
}

// CDC returns the named common data class.
func (m *Model) CDC(name string) (*CDC, bool) {
	c, ok := m.CDCs[name]
	return c, ok
}

// LNClass returns the named logical node class.
func (m *Model) LNClass(name string) (*LNClass, bool) {
	l, ok := m.LNs[name]
	return l, ok
}

// Enum returns the named enumeration.
func (m *Model) Enum(name string) (*Enum, bool) {
	e, ok := m.Enums[name]
	return e, ok
}

// CDCNames returns the class names in table order.
func (m *Model) CDCNames() []string { return append([]string(nil), m.cdcOrder...) }

// LNClassNames returns the logical node class names in table order;
// with group set, only the concrete classes of that group letter.
func (m *Model) LNClassNames(group string) []string {
	var out []string
	for _, n := range m.lnOrder {
		l := m.LNs[n]
		if group == "" || (!l.Abstract && l.Group == group) {
			out = append(out, n)
		}
	}
	return out
}

// MandatoryDataObjects lists the data objects of an LN class that are
// mandatory without condition (for derived statistics with ds).
func (m *Model) MandatoryDataObjects(lnClass string, ds bool) ([]DataObject, error) {
	l, ok := m.LNs[lnClass]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownLNClass, lnClass)
	}
	var out []DataObject
	for _, d := range l.DataObjects {
		if d.Mandatory(ds) {
			out = append(out, d)
		}
	}
	return out, nil
}
