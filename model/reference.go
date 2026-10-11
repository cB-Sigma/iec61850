package model

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Errors of Validate; wrapped with the offending part of the reference.
var (
	ErrSyntax         = errors.New("iec61850 model: malformed object reference")
	ErrUnknownLNClass = errors.New("iec61850 model: unknown logical node class")
	ErrUnknownDO      = errors.New("iec61850 model: data object not in the logical node class")
	ErrUnknownDA      = errors.New("iec61850 model: data attribute not in the common data class")
	ErrFCMismatch     = errors.New("iec61850 model: functional constraint does not match")
	ErrUnknownFC      = errors.New("iec61850 model: unknown functional constraint")
)

// Ref is a parsed object reference LD/LN.DO[.SDO][.DA[.BDA]] (IEC 61850-7-2
// Ed. 2.1 8.2) or its MMS form LD/LN$FC$DO$DA (IEC 61850-8-1).
type Ref struct {
	LD, LN string
	// Prefix, Class and Inst split the LN name (Q0XCBR1: Q0, XCBR, 1).
	Prefix, Class, Inst string
	// Path holds the data object, sub data objects and attributes.
	Path []string
	// FC is the functional constraint of the MMS form (empty otherwise).
	FC string
}

// String gives the dotted form.
func (r Ref) String() string {
	s := r.LN
	if r.LD != "" {
		s = r.LD + "/" + s
	}
	if len(r.Path) > 0 {
		s += "." + strings.Join(r.Path, ".")
	}
	return s
}

// SplitLN splits a logical node name into prefix, class and instance:
// the class is LLN0 or the four letters before the trailing instance digits.
func SplitLN(ln string) (prefix, class, inst string, err error) {
	if ln == "LLN0" {
		return "", "LLN0", "", nil
	}
	rest := strings.TrimRight(ln, "0123456789")
	inst = ln[len(rest):]
	if len(rest) < 4 {
		return "", "", "", fmt.Errorf("%w: logical node name %q", ErrSyntax, ln)
	}
	class = rest[len(rest)-4:]
	prefix = rest[:len(rest)-4]
	for _, c := range class {
		if c < 'A' || c > 'Z' {
			return "", "", "", fmt.Errorf("%w: logical node class in %q", ErrSyntax, ln)
		}
	}
	return prefix, class, inst, nil
}

// ParseRef parses a dotted or MMS ($) object reference. An array index in
// brackets (hstVal[3]) is kept on its element.
func ParseRef(s string) (Ref, error) {
	var r Ref
	s = strings.TrimSpace(s)
	if s == "" {
		return r, fmt.Errorf("%w: empty", ErrSyntax)
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		r.LD, s = s[:i], s[i+1:]
		if r.LD == "" {
			return r, fmt.Errorf("%w: empty logical device", ErrSyntax)
		}
	}
	var parts []string
	if strings.Contains(s, "$") {
		parts = strings.Split(s, "$")
		if len(parts) < 2 {
			return r, fmt.Errorf("%w: %q", ErrSyntax, s)
		}
		r.LN = parts[0]
		r.FC = parts[1]
		parts = parts[2:]
	} else {
		parts = strings.Split(s, ".")
		r.LN, parts = parts[0], parts[1:]
	}
	for _, p := range parts {
		if p == "" {
			return r, fmt.Errorf("%w: empty element in %q", ErrSyntax, s)
		}
	}
	r.Path = parts
	var err error
	r.Prefix, r.Class, r.Inst, err = SplitLN(r.LN)
	return r, err
}

// Resolved is a reference checked against the model.
type Resolved struct {
	Ref
	LNClass *LNClass
	// DO is the data object of the LN class; DOName the name as referenced
	// (with its instance number).
	DO     *DataObject
	DOName string
	// CDC is the class of the innermost data object (a sub data object's
	// class for WYE.phsA).
	CDC *CDC
	// DOPath is the data object part (DO and sub data objects); DAPath the
	// attribute part.
	DOPath, DAPath []string
	// Attr is the top data attribute (nil when the reference ends at a
	// data object); Leaf the innermost element's type name.
	Attr *Attr
	Leaf string
	// FCs are the functional constraints under which the referenced
	// element exists (one for an attribute, all of its attributes' for a
	// data object).
	FCs []string
	// Enum is the enumeration of an enumerated leaf (stVal of an ENS with
	// the data object's enumeration, units.SIUnit …).
	Enum string
	// Control is set when the reference is a control service structure
	// (Oper, SBOw, Cancel, SBO with FC CO).
	Control string
}

var controlStructs = map[string]bool{"Oper": true, "SBOw": true, "Cancel": true, "SBO": true}

// Validate checks an object reference against the model. fc is the
// functional constraint the reference is used with (a configured point's
// FC); it may be empty for the MMS form, which carries its own. A
// reference ending at a data object is valid when the data object has at
// least one attribute with that constraint.
func (m *Model) Validate(ref, fc string) (*Resolved, error) {
	r, err := ParseRef(ref)
	if err != nil {
		return nil, err
	}
	if fc == "" {
		fc = r.FC
	} else if r.FC != "" && r.FC != fc {
		return nil, fmt.Errorf("%w: %s given with %s", ErrFCMismatch, r.FC, fc)
	}
	if fc != "" {
		if _, ok := m.FCs[fc]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownFC, fc)
		}
	}
	l, ok := m.LNs[r.Class]
	if !ok || l.Abstract {
		return nil, fmt.Errorf("%w: %s (in %s)", ErrUnknownLNClass, r.Class, r.LN)
	}
	res := &Resolved{Ref: r, LNClass: l}
	if len(r.Path) == 0 {
		return res, nil
	}
	path := r.Path
	if fc == "CO" && len(path) > 0 && controlStructs[path[0]] {
		// MMS form puts the control structure first: LN$CO$Pos$Oper$ctlVal
		// is Pos.Oper.ctlVal; dotted form keeps it after the DO.
		return nil, fmt.Errorf("%w: control structure %s before the data object", ErrSyntax, path[0])
	}
	doName := stripIndex(path[0])
	do, ok := l.DataObject(doName)
	if !ok {
		return nil, fmt.Errorf("%w: %s.%s", ErrUnknownDO, r.Class, doName)
	}
	res.DO, res.DOName = do, path[0]
	cdc := m.CDCs[do.CDC]
	res.DOPath = []string{path[0]}
	i := 1
	// sub data objects
	for i < len(path) {
		a, ok := cdc.Attr(stripIndex(path[i]))
		if !ok || !a.SubDataObject {
			break
		}
		cdc = m.CDCs[a.Type]
		res.DOPath = append(res.DOPath, path[i])
		i++
	}
	res.CDC = cdc
	if i == len(path) {
		res.FCs = m.cdcFCs(cdc)
		if fc != "" && !contains(res.FCs, fc) {
			return res, fmt.Errorf("%w: %s has no %s attributes", ErrFCMismatch, strings.Join(res.DOPath, "."), fc)
		}
		return res, nil
	}
	res.DAPath = path[i:]
	first := stripIndex(path[i])
	if controlStructs[first] {
		return m.resolveControl(res, cdc, do, fc, path[i+1:], first)
	}
	a, ok := cdc.Attr(first)
	if !ok {
		// setting classes keep the value in a per-FC variant (SPG_SP.setVal)
		for _, v := range m.Variants(cdc.Name) {
			if va, vok := v.Attr(first); vok && (fc == "" || va.FC == fc || !ok) {
				a, ok = va, true
				if fc == "" || va.FC == fc {
					break
				}
			}
		}
	}
	if !ok || a.ServiceParameter {
		return nil, fmt.Errorf("%w: %s.%s", ErrUnknownDA, cdc.Name, first)
	}
	res.Attr = a
	res.FCs = []string{a.FC}
	if fc != "" && a.FC != fc {
		return res, fmt.Errorf("%w: %s.%s is %s, not %s", ErrFCMismatch, cdc.Name, a.Name, a.FC, fc)
	}
	leaf, enum, err := m.walkType(a.Type, path[i+1:])
	if err != nil {
		return nil, err
	}
	if enum == "" {
		enum = m.attrEnum(do, a, leaf)
	}
	res.Leaf, res.Enum = leaf, enum
	return res, nil
}

// attrEnum names the enumeration of an EnumDA-typed attribute: the data
// object's (ENS.stVal, ENC.ctlVal, ENG.setVal).
func (m *Model) attrEnum(do *DataObject, a *Attr, leaf string) string {
	if leaf == "EnumDA" {
		return do.Enum
	}
	if _, ok := m.Enums[leaf]; ok {
		return leaf
	}
	return ""
}

func (m *Model) resolveControl(res *Resolved, cdc *CDC, do *DataObject, fc string, rest []string, st string) (*Resolved, error) {
	ctl, ok := m.Control(cdc.Name)
	if !ok || !ctl.Controllable {
		return nil, fmt.Errorf("%w: %s is not controllable", ErrUnknownDA, cdc.Name)
	}
	if fc != "" && fc != "CO" && !(st == "SBO" && fc == "CO") {
		return res, fmt.Errorf("%w: %s is CO, not %s", ErrFCMismatch, st, fc)
	}
	res.Control, res.FCs = st, []string{"CO"}
	if st == "SBO" {
		if len(rest) > 0 {
			return nil, fmt.Errorf("%w: SBO has no members", ErrUnknownDA)
		}
		res.Leaf = "ObjectReference"
		return res, nil
	}
	if len(rest) == 0 {
		res.Leaf = st
		return res, nil
	}
	fields := ctl.OperFields
	if st == "Cancel" {
		fields = ctl.CancelFields
	}
	for _, f := range fields {
		if f.Name == rest[0] {
			leaf, enum, err := m.walkType(f.Type, rest[1:])
			if err != nil {
				return nil, err
			}
			if enum == "" && leaf == "EnumDA" {
				enum = do.Enum
			}
			res.Leaf, res.Enum = leaf, enum
			return res, nil
		}
	}
	return nil, fmt.Errorf("%w: %s.%s", ErrUnknownDA, st, rest[0])
}

// walkType follows sub-attribute names through constructed types and
// returns the innermost type name and, if it is an enumeration, its name.
func (m *Model) walkType(typ string, rest []string) (string, string, error) {
	for len(rest) > 0 {
		t, ok := m.AttrTypes[typ]
		if !ok {
			return "", "", fmt.Errorf("%w: %s has no member %s", ErrUnknownDA, typ, rest[0])
		}
		name := stripIndex(rest[0])
		var next *Attr
		for j := range t.Attrs {
			a := &t.Attrs[j]
			if a.Name == name {
				next = a
				break
			}
			// packed 7-2 types list nested members as a.b (detailQual.overflow)
			if strings.HasPrefix(a.Name, name+".") && len(rest) > 1 && a.Name == name+"."+rest[1] {
				next = a
				rest = rest[1:]
				break
			}
			if strings.HasPrefix(a.Name, name+".") && len(rest) == 1 {
				next = &Attr{Name: name, Type: "PackedFlags"}
			}
		}
		if next == nil {
			return "", "", fmt.Errorf("%w: %s has no member %s", ErrUnknownDA, typ, rest[0])
		}
		typ = next.Type
		rest = rest[1:]
	}
	if _, ok := m.Enums[typ]; ok {
		return typ, typ, nil
	}
	return typ, "", nil
}

// cdcFCs lists the functional constraints of a class's attributes (sub
// data objects included), plus CO for controllable classes.
func (m *Model) cdcFCs(c *CDC) []string {
	var out []string
	seen := map[string]bool{}
	var walk func(c *CDC)
	walk = func(c *CDC) {
		for _, a := range c.Attrs {
			if a.SubDataObject {
				if s, ok := m.CDCs[a.Type]; ok {
					walk(s)
				}
				continue
			}
			if a.FC != "" && !seen[a.FC] {
				seen[a.FC] = true
				out = append(out, a.FC)
			}
		}
	}
	walk(c)
	for _, v := range m.Variants(c.Name) {
		walk(v)
	}
	if ctl, ok := m.Control(c.Name); ok && ctl.Controllable && !seen["CO"] {
		out = append(out, "CO")
	}
	return out
}

func stripIndex(s string) string {
	if i := strings.IndexByte(s, '['); i > 0 && strings.HasSuffix(s, "]") {
		if _, err := strconv.Atoi(s[i+1 : len(s)-1]); err == nil {
			return s[:i]
		}
	}
	return s
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// Variants returns the per-FC variants of a setting class (SPG_SP, SPG_SG,
// SPG_SE of SPG), in table order.
func (m *Model) Variants(cdc string) []*CDC {
	var out []*CDC
	for _, n := range m.cdcOrder {
		if c := m.CDCs[n]; c.VariantOf == cdc {
			out = append(out, c)
		}
	}
	return out
}
