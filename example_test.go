// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package iec61850_test

import (
	"fmt"

	"github.com/cB-Sigma/iec61850"
)

// Turn a data reference with its functional constraint into the MMS
// variable name the client reads. An association with a device (or with
// the simulated IED of github.com/cB-Sigma/iec61850-sim) is shown in that
// module's Example.
func ExampleParseRef() {
	r, err := iec61850.ParseRef("BAY1/MMXU1.TotW.mag.f", "MX")
	if err != nil {
		fmt.Println(err)
		return
	}
	n := r.MMS()
	fmt.Println(r, n.Domain, n.Item)
	// Output: BAY1/MMXU1.TotW.mag.f BAY1 MMXU1$MX$TotW$mag$f
}

// The Check bits a control carries when its configuration does not say.
func ExampleDefaultChecks() {
	for _, ref := range []string{"LD0/CSWI1.Pos", "LD0/Q0XCBR1.Pos", "LD0/GGIO1.SPCSO1", "LD0/CSWI1$CO$Pos"} {
		i, s := iec61850.DefaultChecks(ref)
		fmt.Println(ref, i, s)
	}
	// Output:
	// LD0/CSWI1.Pos true true
	// LD0/Q0XCBR1.Pos true true
	// LD0/GGIO1.SPCSO1 true false
	// LD0/CSWI1$CO$Pos true true
}
