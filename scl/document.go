package scl

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Document is a parsed SCL file: the lossless tree and the typed model.
type Document struct {
	Tree *Tree
	SCL  *SCL
	// Types indexes the DataTypeTemplates.
	Types *Templates
}

// Parse reads an SCL document. It fails only when the XML is not
// well-formed or the root is not an SCL element; everything else is for
// Validate.
func Parse(raw []byte) (*Document, error) {
	t, err := ParseTree(raw)
	if err != nil {
		return nil, err
	}
	return FromTree(t)
}

// FromTree builds the typed model of a tree (after changes to the tree).
func FromTree(t *Tree) (*Document, error) {
	var s SCL
	if err := xml.Unmarshal(t.normalized(), &s); err != nil {
		return nil, fmt.Errorf("scl: %w", err)
	}
	return &Document{Tree: t, SCL: &s, Types: s.DataTypeTemplates.Index()}, nil
}

// Bytes writes the document back from its tree (lossless).
func (d *Document) Bytes() []byte { return d.Tree.Bytes() }

// IED returns the IED with the name (the first IED for "").
func (d *Document) IED(name string) (*IED, error) {
	if len(d.SCL.IEDs) == 0 {
		return nil, errors.New("scl: the document has no IED")
	}
	if name == "" {
		return &d.SCL.IEDs[0], nil
	}
	for i := range d.SCL.IEDs {
		if d.SCL.IEDs[i].Name == name {
			return &d.SCL.IEDs[i], nil
		}
	}
	return nil, fmt.Errorf("scl: the document has no IED %q", name)
}

// AccessPoint returns an access point of the IED.
func (ied *IED) AccessPoint(name string) *AccessPoint {
	for i := range ied.AccessPoints {
		if ied.AccessPoints[i].Name == name {
			return &ied.AccessPoints[i]
		}
	}
	return nil
}

// LDevice returns the logical device with inst on any server of the IED,
// and the access point that holds it.
func (ied *IED) LDevice(inst string) (*LDevice, *AccessPoint) {
	for i := range ied.AccessPoints {
		ap := &ied.AccessPoints[i]
		if ap.Server == nil {
			continue
		}
		for j := range ap.Server.LDevices {
			if ap.Server.LDevices[j].Inst == inst {
				return &ap.Server.LDevices[j], ap
			}
		}
	}
	return nil, nil
}

// LN finds a logical node of the logical device (class LLN0 or empty
// gives LN0).
func (ld *LDevice) LN(prefix, class, inst string) *LN {
	if class == "LLN0" || class == "" {
		return ld.LN0
	}
	for i := range ld.LNs {
		ln := &ld.LNs[i]
		if ln.LNClass == class && ln.Inst == inst && ln.Prefix == prefix {
			return ln
		}
	}
	return nil
}

// AllLNs returns LN0 (when present) and the other LNs.
func (ld *LDevice) AllLNs() []*LN {
	var out []*LN
	if ld.LN0 != nil {
		out = append(out, ld.LN0)
	}
	for i := range ld.LNs {
		out = append(out, &ld.LNs[i])
	}
	return out
}

// Services returns the effective capability element: at the access point
// when defined there, else at the IED (9.3.2, Table 50).
func (ied *IED) Service(ap *AccessPoint, name string) *ServiceCap {
	if ap != nil {
		if c := ap.Services.Get(name); c != nil {
			return c
		}
	}
	return ied.Services.Get(name)
}

// ConnectedAP returns the ConnectedAP of an IED access point on any
// subnetwork, with the subnetwork.
func (d *Document) ConnectedAP(ied, ap string) (*ConnectedAP, *SubNetwork) {
	if d.SCL.Communication == nil {
		return nil, nil
	}
	for i := range d.SCL.Communication.SubNetworks {
		sn := &d.SCL.Communication.SubNetworks[i]
		for j := range sn.ConnectedAPs {
			c := &sn.ConnectedAPs[j]
			if c.IEDName == ied && (ap == "" || c.APName == ap) {
				return c, sn
			}
		}
	}
	return nil, nil
}

// GSEAddress returns the GSE (or SMV when sv) address element of a
// control block of the IED's logical device.
func (d *Document) GSEAddress(ied, ldInst, cbName string, sv bool) (*GSE, *ConnectedAP) {
	if d.SCL.Communication == nil {
		return nil, nil
	}
	for i := range d.SCL.Communication.SubNetworks {
		sn := &d.SCL.Communication.SubNetworks[i]
		for j := range sn.ConnectedAPs {
			c := &sn.ConnectedAPs[j]
			if c.IEDName != ied {
				continue
			}
			list := c.GSEs
			if sv {
				list = c.SMVs
			}
			for k := range list {
				if list[k].LDInst == ldInst && list[k].CBName == cbName {
					return &list[k], c
				}
			}
		}
	}
	return nil, nil
}

// Attribute is a leaf data attribute of an LN instance expanded from the
// templates, with its instance value from DOI/DAI when set.
type Attribute struct {
	// DO is the data object path (DO[.SDO…]); DA the attribute path
	// (DA[.BDA…]).
	DO, DA string
	FC     string
	BType  string
	// Type is the EnumType id for Enum, DAType id for a Struct parent.
	Type string
	// CDC is the class of the innermost data object.
	CDC string
	// Count is the array size (DA count), 0 when not an array.
	Count string
	// Value and ValKind come from a DAI when present, else from the
	// template's Val and valKind.
	Value, ValKind string
	// SAddr is the short address (instance, else type).
	SAddr string
	// TrgOps are the DA's trigger capabilities (dchg, qchg, dupd).
	TrgOps []string
}

// maxDepth bounds recursive type expansion (recursive SDO references are
// an error, 9.5.3).
const maxDepth = 16

// Expand lists the leaf attributes of an LN instance from its LNodeType,
// in template order, with DOI/DAI instance values applied.
func (d *Document) Expand(ln *LN) ([]Attribute, error) {
	lt, ok := d.Types.LNodeTypes[ln.LNType]
	if !ok {
		return nil, fmt.Errorf("scl: lnType %q of %s is not defined", ln.LNType, ln.Name())
	}
	inst := map[string]DAI{}
	var walkSDI func(path string, sdis []SDI, dais []DAI)
	walkSDI = func(path string, sdis []SDI, dais []DAI) {
		for _, a := range dais {
			inst[path+"."+a.Name] = a
		}
		for _, s := range sdis {
			walkSDI(path+"."+s.Name, s.SDIs, s.DAIs)
		}
	}
	for _, doi := range ln.DOIs {
		walkSDI(doi.Name, doi.SDIs, doi.DAIs)
	}
	var out []Attribute
	var walkDA func(do, cdc, da, fc string, it TypeItem, depth int)
	walkDA = func(do, cdc, da, fc string, it TypeItem, depth int) {
		if it.FC != "" {
			fc = it.FC
		}
		if da != "" {
			da += "."
		}
		da += it.Name
		if it.BType == "Struct" {
			t, ok := d.Types.DATypes[it.Type]
			if !ok || depth > maxDepth {
				return
			}
			for _, b := range t.Members() {
				walkDA(do, cdc, da, fc, b, depth+1)
			}
			return
		}
		a := Attribute{DO: do, DA: da, FC: fc, BType: it.BType, CDC: cdc, Count: it.Count, ValKind: it.ValKind, SAddr: it.SAddr}
		if it.BType == "Enum" {
			a.Type = it.Type
		}
		for _, t := range []struct{ v, n string }{{it.Dchg, "dchg"}, {it.Qchg, "qchg"}, {it.Dupd, "dupd"}} {
			if parseBool(t.v, false) {
				a.TrgOps = append(a.TrgOps, t.n)
			}
		}
		if len(it.Vals) > 0 {
			a.Value = strings.TrimSpace(it.Vals[0].Value)
		}
		if v, ok := inst[do+"."+da]; ok {
			if len(v.Vals) > 0 {
				a.Value = strings.TrimSpace(v.Vals[0].Value)
			}
			if v.ValKind != "" {
				a.ValKind = v.ValKind
			}
			if v.SAddr != "" {
				a.SAddr = v.SAddr
			}
		}
		out = append(out, a)
	}
	var walkDO func(path, typ string, depth int) error
	walkDO = func(path, typ string, depth int) error {
		t, ok := d.Types.DOTypes[typ]
		if !ok {
			return fmt.Errorf("scl: DOType %q of %s.%s is not defined", typ, ln.Name(), path)
		}
		if depth > maxDepth {
			return fmt.Errorf("scl: DOType %q nests too deep (recursive SDO?)", typ)
		}
		for _, m := range t.Members() {
			switch m.Kind() {
			case "SDO":
				if err := walkDO(path+"."+m.Name, m.Type, depth+1); err != nil {
					return err
				}
			case "DA":
				walkDA(path, t.CDC, "", "", m, 0)
			}
		}
		return nil
	}
	for _, do := range lt.DOs {
		if err := walkDO(do.Name, do.Type, 0); err != nil {
			return out, err
		}
	}
	return out, nil
}

// DataObject is a (top level) data object of an LN instance.
type DataObject struct {
	Name, Type, CDC string
	Transient       bool
}

// DataObjects lists the DOs of an LN instance with their CDC.
func (d *Document) DataObjects(ln *LN) []DataObject {
	lt, ok := d.Types.LNodeTypes[ln.LNType]
	if !ok {
		return nil
	}
	var out []DataObject
	for _, do := range lt.DOs {
		cdc := ""
		if t, ok := d.Types.DOTypes[do.Type]; ok {
			cdc = t.CDC
		}
		out = append(out, DataObject{Name: do.Name, Type: do.Type, CDC: cdc, Transient: parseBool(do.Transient, false)})
	}
	return out
}

// Version is an SCL schema version: year, revision letter, release.
type Version struct {
	Year     int
	Revision string
	Release  int
}

// Supported is the version this package implements (Table 53).
var Supported = Version{2007, "C", 5}

// String names the value.
func (v Version) String() string { return fmt.Sprintf("%d%s%d", v.Year, v.Revision, v.Release) }

// Less orders versions.
func (v Version) Less(w Version) bool {
	if v.Year != w.Year {
		return v.Year < w.Year
	}
	if v.Revision != w.Revision {
		return v.Revision < w.Revision
	}
	return v.Release < w.Release
}

// SchemaVersion returns the document's SCL version with the defaults for
// missing attributes (2003, A, 1: 8.2.2 and the root's schema defaults).
func (s *SCL) SchemaVersion() Version {
	v := Version{2003, "A", 1}
	if n, err := strconv.Atoi(strings.TrimSpace(s.Version)); err == nil {
		v.Year = n
	}
	if r := strings.TrimSpace(s.Revision); r != "" {
		v.Revision = r
	}
	if n, err := strconv.Atoi(strings.TrimSpace(s.Release)); err == nil {
		v.Release = n
	}
	return v
}
