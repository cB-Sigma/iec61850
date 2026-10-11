// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package scl_test

import (
	"fmt"

	"github.com/cB-Sigma/iec61850/scl"
)

// Parse an SCL file, check it against the clause rules of IEC 61850-6
// (and the SCL schema, once LoadSchema has been given IEC's schema files)
// and list an IED's logical devices.
func ExampleParse() {
	doc, err := scl.Parse([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="C" release="5">
  <Header id="example" uuid="2f6c0d4e-8a1b-4c3d-9e5f-6a7b8c9d0e1f"/>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <Authentication/>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Beh" type="ENS_Beh"/>
    </LNodeType>
    <DOType id="ENS_Beh" cdc="ENS">
      <DA name="stVal" fc="ST" bType="Enum" type="BehaviourModeKind"/>
      <DA name="q" fc="ST" bType="Quality"/>
      <DA name="t" fc="ST" bType="Timestamp"/>
    </DOType>
    <EnumType id="BehaviourModeKind">
      <EnumVal ord="1">on</EnumVal>
    </EnumType>
  </DataTypeTemplates>
</SCL>`))
	if err != nil {
		fmt.Println(err)
		return
	}
	ied, err := doc.IED("IED1")
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, ap := range ied.AccessPoints {
		for _, ld := range ap.Server.LDevices {
			fmt.Println(ied.Name, ap.Name, ld.Inst)
		}
	}
	v := doc.SCL.SchemaVersion()
	fmt.Println(v.Year, v.Revision, v.Release)
	for _, is := range scl.Validate(doc, scl.Options{}).Errors() {
		fmt.Println(is)
	}
	// Output:
	// IED1 AP1 LD0
	// 2007 C 5
}
