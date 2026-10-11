// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package model_test

import (
	"fmt"
	"os"

	"github.com/cB-Sigma/iec61850/model"
)

// Load IEC's name space definitions (the NSD, SNSD and, optionally, ASD
// files of IEC's NSD zips, unpacked into one directory), look
// up a data object in the IEC 61850-7-4 model and check an object
// reference with its functional constraint. With the 2007B6 NSD files it
// prints "XCBR Pos DPC", "true", "true".
func Example() {
	if err := model.LoadNSD(os.DirFS("iec61850-nsd")); err != nil {
		fmt.Println(err)
		return
	}
	m, err := model.Default()
	if err != nil {
		fmt.Println(err)
		return
	}
	d, _ := m.Describe("XCBR", "Pos")
	fmt.Println(d.LNClass, d.DataObject, d.CDC)
	r, err := m.Validate("LD0/XCBR1.Pos.stVal", "ST")
	fmt.Println(err == nil && r.CDC != nil)
	_, err = m.Validate("LD0/XCBR1.Pos.stVal", "MX")
	fmt.Println(err != nil)
}
