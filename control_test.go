// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package iec61850

import (
	"slices"
	"testing"

	iecmodel "github.com/cB-Sigma/iec61850/model"
)

// Covers: SIG-IPE-2060
func TestControlSequenceFromModel(t *testing.T) {
	for model, want := range map[int][]iecmodel.Service{
		StatusOnly:     nil,
		DirectNormal:   {iecmodel.SvcOperate},
		SBONormal:      {iecmodel.SvcSelect, iecmodel.SvcOperate},
		DirectEnhanced: {iecmodel.SvcOperate, iecmodel.SvcCommandTermination},
		SBOEnhanced:    {iecmodel.SvcSelectWithValue, iecmodel.SvcOperate, iecmodel.SvcCommandTermination},
	} {
		got, err := controlSequence(model)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("ctlModel %d: %v %v", model, got, err)
		}
	}
	if _, err := controlSequence(9); err == nil {
		t.Error("ctlModel 9 accepted")
	}
}

// Controls ask the IED to check its interlocking by default, and switch
// positions of CSWI and XCBR (breakers, disconnectors; any prefix and
// instance, either reference form) also ask for synchrocheck (IEC
// 61850-7-2 control model, Check parameter). SigmaM2M's adapter tests the
// bits on the wire and the explicit opt-out.
//
// Covers: SIG-CMD-207
func TestDefaultChecks(t *testing.T) {
	for ref, want := range map[string]bool{
		"LD0/CSWI1.Pos": true, "LD0/Q0CSWI2.Pos": true, "LD0/XCBR1.Pos": true, "CSWI3.Pos": true, "LD0/CSWI1$CO$Pos": true,
		"LD0/CSWI1.Pos.Oper": true, "LD0/GGIO1.SPCSO1": false, "LD0/CSWI1.BlkOpn": false, "LD0/XSWI1.Pos": false, "LD0/MMXU1": false,
	} {
		interlock, synchro := DefaultChecks(ref)
		if !interlock || synchro != want {
			t.Errorf("%s: interlock %v synchro %v, want true %v", ref, interlock, synchro, want)
		}
	}
}
