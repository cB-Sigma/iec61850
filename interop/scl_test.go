// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/cB-Sigma/iec61850/scl"
)

// sclFiles copies the SCL files of libiec61850's examples, demos and tools
// out of the peer image (they are read at test time, never kept in this
// tree) and returns their paths.
func sclFiles(t *testing.T) (string, []string) {
	t.Helper()
	needDocker(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("docker", "run", "--rm", "-v", dir+":/out", image, "cp", "-r", "/scl/.", "/out/").CombinedOutput()
	if err != nil {
		t.Fatalf("copying the SCL files: %v\n%s", err, out)
	}
	var files []string
	err = filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err == nil && !e.IsDir() {
			files = append(files, p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	if len(files) < 20 {
		t.Fatalf("only %d SCL files", len(files))
	}
	return dir, files
}

// knownBad are libiec61850 files made to hold errors (the model
// generator's negative test input: an AccessPoint without its required
// name, which only the XSD catches).
var knownBad = map[string]bool{"tools/model_generator/sampleModel_errors.icd": true,
	"tools/model_generator_dotnet/Tools/ICDFiles/sampleModel_errors.icd": true}

// defective are libiec61850 files with errors the clause rules find and
// that stay errors in lenient mode, each checked by hand in the file:
// sg_demo.cid declares DOType ids SPS and ENS_Health twice and refers to
// a DAType APCOperate it does not define.
var defective = map[string][]string{
	"examples/server_example_setting_groups/sg_demo.cid": {`"APCOperate" is not a DAType`, `id "SPS" is used by DOType and DOType`,
		`id "ENS_Health" is used by DOType and DOType`},
}

// schemaDir is the SCL schema directory: SIGMA_SCL_SCHEMA_DIR, else the
// SCL schema under IEC61850_CODE_COMPONENTS; "" when neither is set.
func schemaDir() string {
	if d := os.Getenv("SIGMA_SCL_SCHEMA_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("IEC61850_CODE_COMPONENTS"); d != "" {
		return filepath.Join(d, "IEC_61850-6.SCL.2007C5")
	}
	return ""
}

// TestSCLFiles parses every SCL file of libiec61850 v1.6.2.1 with
// scl.Parse, builds each IED's model, and validates it with the clause
// rules (and the XSD when SIGMA_SCL_SCHEMA_DIR names a directory with
// SCL.xsd).
func TestSCLFiles(t *testing.T) {
	dir, files := sclFiles(t)
	schema := schemaDir()
	if schema != "" {
		if err := scl.LoadSchema(os.DirFS(schema)); err != nil {
			t.Fatalf("loading the SCL schema from %s: %v", schema, err)
		}
		t.Logf("SCL schema %s loaded from %s", scl.SchemaVersion(), schema)
	}
	for _, f := range files {
		rel, _ := filepath.Rel(dir, f)
		rel = filepath.ToSlash(rel)
		t.Run(rel, func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			d, err := scl.Parse(raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			// Every IED's data model expands from the templates.
			for _, ied := range d.SCL.IEDs {
				if _, err := d.IED(ied.Name); err != nil {
					t.Errorf("IED %s: %v", ied.Name, err)
				}
				for _, ap := range ied.AccessPoints {
					if ap.Server == nil {
						continue
					}
					for _, ld := range ap.Server.LDevices {
						for _, ln := range ld.AllLNs() {
							if _, err := d.Expand(ln); err != nil && !knownBad[rel] {
								t.Errorf("IED %s LD %s LN %s: %v", ied.Name, ld.Inst, ln.Name(), err)
							}
						}
					}
				}
			}
			strict := scl.Validate(d, scl.Options{})
			lenient := scl.Validate(d, scl.Options{Lenient: true})
			var structural []string
			for _, i := range lenient.Errors() {
				structural = append(structural, i.String())
			}
			t.Logf("%d IEDs; strict: %d errors, %d issues; lenient: %d errors", len(d.SCL.IEDs), len(strict.Errors()), len(strict), len(structural))
			for _, i := range strict.Errors() {
				t.Logf("  %s", i)
			}
			if knownBad[rel] {
				for _, i := range strict {
					t.Logf("  %s", i)
				}
				// The file is SCL 2003 (no version attribute): departures from
				// the 2007 schema are warnings for it.
				if schema != "" && !strict.Has("required attribute name is missing") {
					t.Error("the AccessPoint without a name is not reported")
				}
				return
			}
			if want, ok := defective[rel]; ok {
				for _, w := range want {
					if !lenient.Errors().Has(w) {
						t.Errorf("the known defect %q is not reported", w)
					}
				}
				if len(structural) != len(want) {
					t.Errorf("structural errors:\n%s", strings.Join(structural, "\n"))
				}
				return
			}
			if len(structural) > 0 {
				t.Errorf("structural errors:\n%s", strings.Join(structural, "\n"))
			}
		})
	}
}
