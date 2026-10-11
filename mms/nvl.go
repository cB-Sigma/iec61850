package mms

import (
	"context"
	"errors"
)

// Additive exports used by other MMS-based adapters (ICCP / TASE.2): a
// generic confirmed-service call and the named variable list definition
// services (ISO 9506-2, DefineNamedVariableList and
// DeleteNamedVariableList).

// Confirmed service numbers of the named variable list services.
const (
	SvcDefineNamedVariableList = 11
	SvcDeleteNamedVariableList = 13
)

// Call sends a confirmed request whose service element is service (the
// context-tagged ConfirmedServiceRequest alternative) and returns the
// response's service element, which must be alternative want.
func (c *Client) Call(ctx context.Context, service []byte, want int) (Elem, error) {
	return c.call(ctx, service, want)
}

// DefineNamedVariableListRequest defines a named variable list (a data
// set) whose members are named variables.
func DefineNamedVariableListRequest(name ObjectName, members []ObjectName) []byte {
	return T(0xa0|SvcDefineNamedVariableList, name.Encode(), VariableSpec{Vars: members}.Encode())
}

// DeleteNamedVariableListRequest deletes specific named variable lists.
func DeleteNamedVariableListRequest(names ...ObjectName) []byte {
	items := make([][]byte, len(names))
	for i, n := range names {
		items[i] = n.Encode()
	}
	return T(0xa0|SvcDeleteNamedVariableList, Int(0x80, 0), T(0xa1, items...))
}

// DefineNamedVariableList defines a named variable list on the server.
func (c *Client) DefineNamedVariableList(ctx context.Context, name ObjectName, members []ObjectName) error {
	_, err := c.call(ctx, DefineNamedVariableListRequest(name, members), SvcDefineNamedVariableList)
	return err
}

// DeleteNamedVariableList deletes named variable lists and returns how
// many the server matched and deleted.
func (c *Client) DeleteNamedVariableList(ctx context.Context, names ...ObjectName) (matched, deleted uint64, err error) {
	body, err := c.call(ctx, DeleteNamedVariableListRequest(names...), SvcDeleteNamedVariableList)
	if err != nil {
		return 0, 0, err
	}
	kids, err := body.Children()
	if err != nil {
		return 0, 0, err
	}
	for _, k := range kids {
		switch {
		case k.Context(0):
			matched, _ = DecodeUint(k.Val)
		case k.Context(1):
			deleted, _ = DecodeUint(k.Val)
		}
	}
	return matched, deleted, nil
}

// DefineNamedVariableListArgs decodes a DefineNamedVariableList request
// (server side).
func DefineNamedVariableListArgs(body Elem) (ObjectName, []ObjectName, error) {
	name, spec, err := DefineNamedVariableListSpec(body)
	return name, spec.Vars, err
}

// DefineNamedVariableListSpec decodes a DefineNamedVariableList request
// with the members' alternate access (spec.Alt; server side).
func DefineNamedVariableListSpec(body Elem) (ObjectName, VariableSpec, error) {
	kids, err := body.Children()
	if err != nil || len(kids) != 2 {
		return ObjectName{}, VariableSpec{}, errors.New("mms: a bad define named variable list request")
	}
	name, err := DecodeObjectName(kids[0])
	if err != nil {
		return ObjectName{}, VariableSpec{}, err
	}
	spec, err := DecodeVariableSpec(Elem{Tag: 0xa0, Num: 0, Val: kids[1].Val})
	if err != nil {
		return ObjectName{}, VariableSpec{}, err
	}
	return name, spec, nil
}

// DefineNamedVariableListSpecRequest defines a list whose members may have
// an alternate access (spec.Alt).
func DefineNamedVariableListSpecRequest(name ObjectName, spec VariableSpec) []byte {
	spec.ListName = nil
	return T(0xa0|SvcDefineNamedVariableList, name.Encode(), T(0xa0, specItems(spec)))
}

// specItems is the content of a listOfVariable.
func specItems(spec VariableSpec) []byte {
	e, _, _ := Parse(spec.Encode())
	return e.Val
}

// NamedVariableListAttributesSpecResponse answers
// GetNamedVariableListAttributes with the members and their alternate
// access.
func NamedVariableListAttributesSpecResponse(spec VariableSpec, deletable bool) []byte {
	spec.ListName = nil
	return T(0xa0|SvcGetNamedVariableListAttributes, Bool(0x80, deletable), T(0xa1, specItems(spec)))
}

// GetNamedVariableListSpec returns a named variable list's members with
// their alternate access (spec.Alt), as the server defined them.
func (c *Client) GetNamedVariableListSpec(ctx context.Context, n ObjectName) (VariableSpec, error) {
	body, err := c.call(ctx, GetNamedVariableListAttributesRequest(n), SvcGetNamedVariableListAttributes)
	if err != nil {
		return VariableSpec{}, err
	}
	return decodeNVLASpec(body)
}

// DeleteNamedVariableListArgs decodes the specific list names of a
// DeleteNamedVariableList request (server side).
func DeleteNamedVariableListArgs(body Elem) ([]ObjectName, error) {
	kids, err := body.Children()
	if err != nil {
		return nil, err
	}
	var out []ObjectName
	for _, k := range kids {
		if !k.Context(1) {
			continue
		}
		items, err := k.Children()
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			n, err := DecodeObjectName(it)
			if err != nil {
				return nil, err
			}
			out = append(out, n)
		}
	}
	return out, nil
}

// DefineNamedVariableListResponse answers DefineNamedVariableList.
func DefineNamedVariableListResponse() []byte { return T(0x80 | SvcDefineNamedVariableList) }

// DeleteNamedVariableListResponse answers DeleteNamedVariableList.
func DeleteNamedVariableListResponse(matched, deleted int) []byte {
	return T(0xa0|SvcDeleteNamedVariableList, Uint(0x80, uint64(matched)), Uint(0x81, uint64(deleted)))
}
