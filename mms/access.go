package mms

import (
	"errors"
	"fmt"
)

// Alternate access (ISO 9506-2:2003 14.3.1, ISO 9506-1:2003 14.3): a
// selection of parts of a variable, the valt parameter CBB.

// Access selection kinds.
const (
	AltComponent  = iota // a structure component by name
	AltIndex             // one array element
	AltIndexRange        // Count array elements from Index
	AltAll               // every array element
)

// AltSelection is one element of an AlternateAccess: a selection and, for
// selectAlternateAccess, the alternate access applied to what it selects.
// Name, when set, is the component name the selected part carries in the
// result (the named choice).
type AltSelection struct {
	Name      string
	Kind      int
	Component string
	Index     uint32
	Count     uint32
	Nested    AlternateAccess
}

// AlternateAccess is a list of selections; one selection yields the
// selected part, several yield a structure of the parts.
type AlternateAccess []AltSelection

// Encode encodes the list's elements (the caller supplies the tag of the
// SEQUENCE OF: 0xa5 for the alternateAccess of a variable, 0x30 nested).
func (a AlternateAccess) elements() [][]byte {
	out := make([][]byte, len(a))
	for i, s := range a {
		sel := s.encodeSelection()
		if s.Name != "" {
			sel = T(0xa5, Str(0x80, s.Name), sel)
		}
		out[i] = sel
	}
	return out
}

// encodeSelection encodes the AlternateAccessSelection CHOICE: with a
// nested access, selectAlternateAccess [0] {accessSelection, alternateAccess};
// else selectAccess (component [1], index [2], indexRange [3],
// allElements [4]).
func (s AltSelection) encodeSelection() []byte {
	if len(s.Nested) > 0 {
		var acc []byte
		switch s.Kind {
		case AltComponent:
			acc = Str(0x80, s.Component)
		case AltIndex:
			acc = Uint(0x81, uint64(s.Index))
		case AltIndexRange:
			acc = T(0xa2, Uint(0x80, uint64(s.Index)), Uint(0x81, uint64(s.Count)))
		default:
			acc = T(0x83)
		}
		return T(0xa0, acc, T(0x30, s.Nested.elements()...))
	}
	switch s.Kind {
	case AltComponent:
		return Str(0x81, s.Component)
	case AltIndex:
		return Uint(0x82, uint64(s.Index))
	case AltIndexRange:
		return T(0xa3, Uint(0x80, uint64(s.Index)), Uint(0x81, uint64(s.Count)))
	}
	return T(0x84)
}

// DecodeAlternateAccess decodes the contents of an AlternateAccess.
func DecodeAlternateAccess(b []byte) (AlternateAccess, error) {
	kids, err := ParseAll(b)
	if err != nil {
		return nil, err
	}
	out := make(AlternateAccess, 0, len(kids))
	for _, k := range kids {
		var s AltSelection
		if k.Tag == 0xa5 { // named
			parts, err := k.Children()
			if err != nil || len(parts) != 2 || parts[0].Tag != 0x80 {
				return nil, errors.New("mms: a bad named alternate access")
			}
			s.Name = string(parts[0].Val)
			k = parts[1]
		}
		if err := s.decodeSelection(k); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (s *AltSelection) decodeSelection(k Elem) error {
	range2 := func(e Elem) error {
		parts, err := e.Children()
		if err != nil || len(parts) != 2 {
			return errors.New("mms: a bad index range")
		}
		lo, err1 := DecodeUint(parts[0].Val)
		n, err2 := DecodeUint(parts[1].Val)
		if err1 != nil || err2 != nil {
			return errors.New("mms: a bad index range")
		}
		s.Kind, s.Index, s.Count = AltIndexRange, uint32(lo), uint32(n)
		return nil
	}
	switch k.Tag {
	case 0xa0: // selectAlternateAccess
		parts, err := k.Children()
		if err != nil || len(parts) != 2 || parts[1].Tag != 0x30 {
			return errors.New("mms: a bad selectAlternateAccess")
		}
		switch a := parts[0]; a.Tag {
		case 0x80:
			s.Kind, s.Component = AltComponent, string(a.Val)
		case 0x81:
			v, err := DecodeUint(a.Val)
			if err != nil {
				return err
			}
			s.Kind, s.Index = AltIndex, uint32(v)
		case 0xa2:
			if err := range2(a); err != nil {
				return err
			}
		case 0x83:
			s.Kind = AltAll
		default:
			return fmt.Errorf("mms: access selection with tag %#x", a.Tag)
		}
		if s.Nested, err = DecodeAlternateAccess(parts[1].Val); err != nil {
			return err
		}
		if len(s.Nested) == 0 {
			return errors.New("mms: an empty nested alternate access")
		}
	case 0x81:
		s.Kind, s.Component = AltComponent, string(k.Val)
	case 0x82:
		v, err := DecodeUint(k.Val)
		if err != nil {
			return err
		}
		s.Kind, s.Index = AltIndex, uint32(v)
	case 0xa3:
		return range2(k)
	case 0x84:
		s.Kind = AltAll
	default:
		return fmt.Errorf("mms: alternate access selection with tag %#x", k.Tag)
	}
	return nil
}

// ApplyAlternateAccess selects the parts of a value a names, using the
// value's type for component names. It returns the selected value and its
// type; a selection that does not fit the type fails with
// ErrTypeInconsistent, a missing component or index with
// ErrObjectNonExistent (our choice of DataAccessError, findings F-697).
func ApplyAlternateAccess(d Data, t TypeSpec, a AlternateAccess) (Data, TypeSpec, error) {
	if len(a) == 1 && a[0].Name == "" {
		return applySel(d, t, a[0])
	}
	out := Data{Kind: KStructure}
	ot := TypeSpec{Kind: KStructure}
	for _, s := range a {
		v, vt, err := applySel(d, t, s)
		if err != nil {
			return Data{}, TypeSpec{}, err
		}
		out.Elems = append(out.Elems, v)
		ot.Components = append(ot.Components, Component{Name: s.Name, Type: vt})
	}
	return out, ot, nil
}

func applySel(d Data, t TypeSpec, s AltSelection) (Data, TypeSpec, error) {
	var v Data
	var vt TypeSpec
	each := false
	switch s.Kind {
	case AltComponent:
		if d.Kind != KStructure || t.Kind != KStructure || len(t.Components) != len(d.Elems) {
			return Data{}, TypeSpec{}, ErrTypeInconsistent
		}
		ct, i, ok := t.Find(s.Component)
		if !ok {
			return Data{}, TypeSpec{}, ErrObjectNonExistent
		}
		v, vt = d.Elems[i], ct
	case AltIndex:
		if d.Kind != KArray || t.Kind != KArray || t.Elem == nil {
			return Data{}, TypeSpec{}, ErrTypeInconsistent
		}
		if int(s.Index) >= len(d.Elems) {
			return Data{}, TypeSpec{}, ErrObjectNonExistent
		}
		v, vt = d.Elems[s.Index], *t.Elem
	case AltIndexRange, AltAll:
		if d.Kind != KArray || t.Kind != KArray || t.Elem == nil {
			return Data{}, TypeSpec{}, ErrTypeInconsistent
		}
		lo, n := 0, len(d.Elems)
		if s.Kind == AltIndexRange && !(s.Index == 0 && s.Count == 0) { // 0, 0 is all elements (14.3.1)
			lo, n = int(s.Index), int(s.Count)
			if lo+n > len(d.Elems) || n == 0 {
				return Data{}, TypeSpec{}, ErrObjectNonExistent
			}
		}
		v = Data{Kind: KArray, Elems: append([]Data(nil), d.Elems[lo:lo+n]...)}
		el := *t.Elem
		vt = TypeSpec{Kind: KArray, Elements: n, Elem: &el}
		each = true
	default:
		return Data{}, TypeSpec{}, ErrTypeInconsistent
	}
	if len(s.Nested) == 0 {
		return v, vt, nil
	}
	if !each {
		return ApplyAlternateAccess(v, vt, s.Nested)
	}
	// The nested access applies to each selected element.
	out := Data{Kind: KArray}
	var et TypeSpec
	for _, e := range v.Elems {
		ev, t2, err := ApplyAlternateAccess(e, *vt.Elem, s.Nested)
		if err != nil {
			return Data{}, TypeSpec{}, err
		}
		out.Elems = append(out.Elems, ev)
		et = t2
	}
	if len(v.Elems) == 0 {
		return out, vt, nil
	}
	return out, TypeSpec{Kind: KArray, Elements: len(out.Elems), Elem: &et}, nil
}
