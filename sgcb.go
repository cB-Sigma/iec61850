package iec61850

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

// SGCB is the state of a logical device's setting group control block
// (IEC 61850-7-2 setting group control, mapped by IEC 61850-8-1 16.1 Table
// 71 to the structure LLN0$SP$SGCB: NumOfSG, ActSG, EditSG, CnfEdit,
// LActTm, ResvTms).
type SGCB struct {
	NumOfSG int `json:"numOfSG"`
	ActSG   int `json:"actSG"`
	EditSG  int `json:"editSG"`
	// LActTm is when the active group last changed (RFC 3339; empty when
	// the IED has no LActTm or has not set it).
	LActTm string `json:"lActTm,omitempty"`
	// ResvTms is the edit reservation time in seconds (edition 2 IEDs).
	ResvTms *int `json:"resvTms,omitempty"`
}

func sgcbAttr(ld, attr string) mms.ObjectName { return mms.DomainName(ld, "LLN0$SP$SGCB$"+attr) }

func asInt(d mms.Data) (int, bool) {
	switch d.Kind {
	case mms.KUint:
		return int(d.Uint), true
	case mms.KInt:
		return int(d.Int), true
	}
	return 0, false
}

// ReadSGCB reads ld's setting group control block (GetSGCBValues, 8-1
// 16.2.6: a read of the whole structure).
func (cl *Client) ReadSGCB(ctx context.Context, ld string) (SGCB, error) {
	n := mms.DomainName(ld, "LLN0$SP$SGCB")
	t, err := cl.TypeOf(ctx, n)
	if err != nil {
		return SGCB{}, err
	}
	d, err := cl.c.ReadOne(ctx, n)
	if err != nil {
		return SGCB{}, fmt.Errorf("reading %s: %w", n, err)
	}
	if t.Kind != mms.KStructure || d.Kind != mms.KStructure || len(d.Elems) != len(t.Components) {
		return SGCB{}, fmt.Errorf("%s is not a setting group control block", n)
	}
	var out SGCB
	seen := 0
	for i, c := range t.Components {
		v := d.Elems[i]
		switch c.Name {
		case "NumOfSG", "ActSG", "EditSG":
			x, ok := asInt(v)
			if !ok {
				return SGCB{}, fmt.Errorf("%s$%s is not an integer", n, c.Name)
			}
			seen++
			switch c.Name {
			case "NumOfSG":
				out.NumOfSG = x
			case "ActSG":
				out.ActSG = x
			default:
				out.EditSG = x
			}
		case "LActTm":
			if v.Kind == mms.KUTCTime && !v.Time.T.IsZero() && v.Time.T.Unix() != 0 {
				out.LActTm = v.Time.T.UTC().Format(time.RFC3339Nano)
			}
		case "ResvTms":
			if x, ok := asInt(v); ok {
				out.ResvTms = &x
			}
		}
	}
	if seen != 3 {
		return SGCB{}, errors.New("the setting group control block lacks NumOfSG, ActSG or EditSG")
	}
	return out, nil
}

// writeSGCB writes an SGCB attribute with the type the IED declares.
func (cl *Client) writeSGCB(ctx context.Context, ld, attr string, v any) error {
	n := sgcbAttr(ld, attr)
	t, err := cl.TypeOf(ctx, n)
	if err != nil {
		return err
	}
	d, err := FromJSON(t, v)
	if err != nil {
		return fmt.Errorf("%s: %w", attr, err)
	}
	if err := cl.c.WriteOne(ctx, n, d); err != nil {
		return fmt.Errorf("writing %s of %s: %w", attr, ld, err)
	}
	return nil
}

// SelectActiveSG makes setting group n (1..NumOfSG) of ld active.
func (cl *Client) SelectActiveSG(ctx context.Context, ld string, n int) error {
	return cl.writeSGCB(ctx, ld, "ActSG", n)
}

// SelectEditSG selects setting group n of ld for editing (0 ends editing
// without confirming).
func (cl *Client) SelectEditSG(ctx context.Context, ld string, n int) error {
	return cl.writeSGCB(ctx, ld, "EditSG", n)
}

// ConfirmEditSGValues stores the edited SE values into the group being
// edited.
func (cl *Client) ConfirmEditSGValues(ctx context.Context, ld string) error {
	return cl.writeSGCB(ctx, ld, "CnfEdit", true)
}
