// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package scl

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cB-Sigma/iec61850/model"
)

// The SCL schema, the NSD files and SCL files built around the standard's
// examples are IEC material that this module does not carry. The tests
// read them from
//
//   - $IEC61850_CODE_COMPONENTS: a directory holding IEC's unpacked zips,
//     among them the NSD files and the SCL schema (IEC_61850-6.SCL.*);
//   - $IEC61850_SCL_TESTDATA: SCL test files built around the standard's
//     examples (clause9.scd, coordinates_annex_c.scd, ssd_9_2_8.ssd).
//
// Tests that need them are skipped without them; testdata/bay.scd is this
// module's own.

var testSchemaErr, testNSDErr error

func TestMain(m *testing.M) {
	testSchemaErr = errors.New("the SCL schema is not here (set IEC61850_CODE_COMPONENTS)")
	testNSDErr = errors.New("IEC's NSD files are not here (set IEC61850_CODE_COMPONENTS)")
	if dir := os.Getenv("IEC61850_CODE_COMPONENTS"); dir != "" {
		if m, _ := filepath.Glob(filepath.Join(dir, "IEC_61850-6.SCL.*", "SCL.xsd")); len(m) > 0 {
			testSchemaErr = LoadSchema(os.DirFS(filepath.Dir(m[len(m)-1])))
		}
		testNSDErr = model.LoadNSD(os.DirFS(dir))
	}
	os.Exit(m.Run())
}

// needSchema skips a test that needs the SCL schema.
func needSchema(t testing.TB) {
	t.Helper()
	if testSchemaErr != nil {
		t.Skip(testSchemaErr)
	}
}

// needNSD skips a test that needs the IEC 61850 model.
func needNSD(t testing.TB) {
	t.Helper()
	if testNSDErr != nil {
		t.Skip(testNSDErr)
	}
}

// testFile is the path of an SCL test file: this module's own in
// testdata, or one of the files built around the standard's examples.
func testFile(t testing.TB, name string) string {
	t.Helper()
	if p := filepath.Join("testdata", name); fileExists(p) {
		return p
	}
	p := filepath.Join(os.Getenv("IEC61850_SCL_TESTDATA"), name)
	if os.Getenv("IEC61850_SCL_TESTDATA") == "" || !fileExists(p) {
		t.Skipf("%s is not here: it is built around the standard's examples (set IEC61850_SCL_TESTDATA)", name)
	}
	needSchema(t)
	return p
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
