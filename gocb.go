// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package iec61850

import (
	"context"
	"fmt"
	"sort"

	"github.com/cB-Sigma/iec61850/mms"
)

// GOOSE and multicast sampled value control blocks over MMS (IEC 61850-7-2
// GoCB and MSVCB services, mapped by IEC 61850-8-1 to the structures
// LLN0$GO$<name> and LLN0$MS$<name>): GetGoCBValues and SetGoCBValues,
// GetMSVCBValues and SetMSVCBValues. The values are the attributes the
// IED declares, by name, as JSON values (ToJSON, FromJSON).

// gocbRef is the MMS name of a control block of functional constraint fc.
func gocbRef(ld, fc, name string) mms.ObjectName {
	return mms.DomainName(ld, "LLN0$"+fc+"$"+name)
}

// cbValues reads a control block structure and returns its attributes as
// JSON values.
func (cl *Client) cbValues(ctx context.Context, n mms.ObjectName, what string) (map[string]any, error) {
	t, err := cl.TypeOf(ctx, n)
	if err != nil {
		return nil, err
	}
	d, err := cl.c.ReadOne(ctx, n)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", n, err)
	}
	if t.Kind != mms.KStructure || d.Kind != mms.KStructure || len(d.Elems) != len(t.Components) {
		return nil, fmt.Errorf("%s is not a %s", n, what)
	}
	out := make(map[string]any, len(d.Elems))
	for i, c := range t.Components {
		out[c.Name] = ToJSON(&t.Components[i].Type, d.Elems[i], c.Name)
	}
	return out, nil
}

// setCBValues writes attributes of a control block, each with the type the
// IED declares, in a stable order (the enable flag last, so the other
// attributes are set before the block starts publishing).
func (cl *Client) setCBValues(ctx context.Context, n mms.ObjectName, enable string, vals map[string]any) error {
	t, err := cl.TypeOf(ctx, n)
	if err != nil {
		return err
	}
	if t.Kind != mms.KStructure {
		return fmt.Errorf("%s is not a control block", n)
	}
	types := map[string]mms.TypeSpec{}
	for _, c := range t.Components {
		types[c.Name] = c.Type
	}
	names := make([]string, 0, len(vals))
	for k := range vals {
		if _, ok := types[k]; !ok {
			return fmt.Errorf("%s has no attribute %s", n, k)
		}
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool {
		if (names[i] == enable) != (names[j] == enable) {
			return names[j] == enable
		}
		return names[i] < names[j]
	})
	for _, k := range names {
		d, err := FromJSON(types[k], vals[k])
		if err != nil {
			return fmt.Errorf("%s$%s: %w", n, k, err)
		}
		an := n
		an.Item += "$" + k
		if err := cl.c.WriteOne(ctx, an, d); err != nil {
			return fmt.Errorf("writing %s: %w", an, err)
		}
	}
	return nil
}

// GoCBValues reads the GOOSE control block name of ld (GetGoCBValues):
// GoEna, GoID, DatSet, ConfRev, NdsCom, DstAddress, MinTime, MaxTime,
// FixedOffs and whatever else the IED declares.
func (cl *Client) GoCBValues(ctx context.Context, ld, name string) (map[string]any, error) {
	return cl.cbValues(ctx, gocbRef(ld, "GO", name), "GOOSE control block")
}

// SetGoCBValues writes attributes of a GOOSE control block
// (SetGoCBValues), GoEna last.
func (cl *Client) SetGoCBValues(ctx context.Context, ld, name string, vals map[string]any) error {
	return cl.setCBValues(ctx, gocbRef(ld, "GO", name), "GoEna", vals)
}

// EnableGoCB starts or stops the publication of a GOOSE control block.
func (cl *Client) EnableGoCB(ctx context.Context, ld, name string, on bool) error {
	return cl.SetGoCBValues(ctx, ld, name, map[string]any{"GoEna": on})
}

// MSVCBValues reads the multicast sampled value control block name of ld
// (GetMSVCBValues): SvEna, MsvID, DatSet, ConfRev, SmpRate, OptFlds,
// SmpMod, DstAddress, noASDU and whatever else the IED declares.
func (cl *Client) MSVCBValues(ctx context.Context, ld, name string) (map[string]any, error) {
	return cl.cbValues(ctx, gocbRef(ld, "MS", name), "multicast sampled value control block")
}

// SetMSVCBValues writes attributes of a multicast sampled value control
// block (SetMSVCBValues), SvEna last.
func (cl *Client) SetMSVCBValues(ctx context.Context, ld, name string, vals map[string]any) error {
	return cl.setCBValues(ctx, gocbRef(ld, "MS", name), "SvEna", vals)
}
