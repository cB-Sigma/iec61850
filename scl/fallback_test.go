// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package scl

import (
	"slices"
	"testing"

	"github.com/cB-Sigma/iec61850/model"
)

// TestExportFallbacksMatchModel: the facts the gateway export uses when
// IEC's NSD files are not loaded (control service members, enumeration
// literals) are those of the model built from the NSD files.
func TestExportFallbacksMatchModel(t *testing.T) {
	needNSD(t)
	m, err := model.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, cdc := range []string{"SPC", "INC", "DPC"} {
		ci, ok := m.Control(cdc)
		if !ok {
			t.Fatalf("%s: no control", cdc)
		}
		want := []string{"ctlVal", "operTm", "origin", "ctlNum", "T", "Test", "Check"}
		var got []string
		for _, f := range ci.OperFields {
			got = append(got, f.Name)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s Oper members %v, fallback %v", cdc, got, want)
		}
		got = got[:0]
		for _, f := range ci.CancelFields {
			got = append(got, f.Name)
		}
		if !slices.Equal(got, want[:6]) {
			t.Errorf("%s Cancel members %v, fallback %v", cdc, got, want[:6])
		}
		for _, f := range ci.OperFields {
			for _, fb := range []model.Attr{{Name: "ctlNum", Type: "INT8U"}, {Name: "T", Type: "Timestamp"}, {Name: "Test", Type: "BOOLEAN"}, {Name: "Check", Type: "CheckConditions"}} {
				if f.Name == fb.Name && f.Type != fb.Type {
					t.Errorf("%s.%s type %s, fallback %s", cdc, f.Name, f.Type, fb.Type)
				}
			}
		}
	}
	for name, lits := range fallbackEnums {
		en, ok := m.Enum(name)
		if !ok {
			t.Fatalf("enumeration %s not in the model", name)
		}
		for i, lit := range lits {
			if got, _ := en.Literal(i); got != lit {
				t.Errorf("%s(%d) = %q in the model, fallback %q", name, i, got, lit)
			}
		}
	}
}

// TestValidateWithoutSchema: without the SCL schema the clause rules
// still run and one warning says the schema checks were skipped.
func TestValidateWithoutSchema(t *testing.T) {
	schemaMu.Lock()
	saved := schemaIdx
	schemaIdx = nil
	schemaMu.Unlock()
	t.Cleanup(func() {
		schemaMu.Lock()
		schemaIdx = saved
		schemaMu.Unlock()
	})
	d, _ := load(t, "bay.scd")
	is := Validate(d, Options{FileType: "SCD"})
	if !is.Has("schema checks were skipped") {
		t.Errorf("no warning about the missing schema: %v", is)
	}
	if e := errorsOf(is); len(e) > 0 {
		t.Errorf("bay.scd errors: %v", e)
	}
	if SchemaVersion() != "" {
		t.Errorf("SchemaVersion without a schema = %q", SchemaVersion())
	}
}

// TestOwnSystem: this module's own test system parses, validates and
// expands.
func TestOwnSystem(t *testing.T) {
	d, _ := load(t, "bay.scd")
	is := Validate(d, Options{FileType: "SCD"})
	if e := errorsOf(is); len(e) > 0 {
		t.Errorf("bay.scd errors: %v", e)
	}
	ied, err := d.IED("BAY7CTRL")
	if err != nil {
		t.Fatal(err)
	}
	ld, _ := ied.LDevice("CTRL")
	if ld.Name(ied.Name) != "BAY7CTRLCTRL" {
		t.Errorf("LD name = %s", ld.Name(ied.Name))
	}
	rc := ld.LN0.ReportControls[0]
	if !slices.Equal(rc.Instances(), []string{"SwitchRpt01", "SwitchRpt02", "SwitchRpt03"}) || rc.IsBuffered() {
		t.Errorf("report instances = %v", rc.Instances())
	}
	if !ld.LN0.ReportControls[1].IsBuffered() {
		t.Error("VoltsBuf is buffered")
	}
	a, gse := d.GSEAddress("BAY7CTRL", "CTRL", "Interlock", false)
	if a == nil || gse.APName != "P1" {
		t.Fatal("GSE address of Interlock not found")
	}
	if mac, _ := a.Address.Get("MAC-Address"); mac != "01-0C-CD-01-07-10" {
		t.Errorf("mac = %s", mac)
	}
	var mmxu *LN
	for _, ln := range ld.AllLNs() {
		if ln.Name() == "MMXU1" {
			mmxu = ln
		}
	}
	attrs, err := d.Expand(mmxu)
	if err != nil {
		t.Fatal(err)
	}
	vals := map[string]string{}
	for _, at := range attrs {
		vals[at.DO+"."+at.DA+"["+at.FC+"]"] = at.Value
	}
	if vals["TotW.sVC.scaleFactor[CF]"] != "0.5" || vals["TotW.units.SIUnit[CF]"] != "W" {
		t.Errorf("expanded values = %v", vals)
	}
}
