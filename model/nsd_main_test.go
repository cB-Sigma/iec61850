// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"errors"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// The NSD files are IEC's, which this module does not carry. The tests
// load them from $IEC61850_CODE_COMPONENTS, a directory holding IEC's
// unpacked NSD, SNSD and ASD zips; LN titles and abbreviation meanings
// come from $IEC61850_DESCRIPTIONS (a YAML file with lnTitles and
// abbreviations maps). Tests that need them are skipped without them.

var (
	testNSDErr  error
	testDescsOK bool
)

func TestMain(m *testing.M) {
	if dir := os.Getenv("IEC61850_CODE_COMPONENTS"); dir == "" {
		testNSDErr = errors.New("IEC's NSD files are not here (set IEC61850_CODE_COMPONENTS)")
	} else {
		testNSDErr = LoadNSD(os.DirFS(dir))
	}
	if b, err := os.ReadFile(os.Getenv("IEC61850_DESCRIPTIONS")); err == nil {
		var d struct {
			LNTitles      map[string]string `yaml:"lnTitles"`
			Abbreviations map[string]string `yaml:"abbreviations"`
		}
		if yaml.Unmarshal(b, &d) == nil && len(d.LNTitles) > 0 {
			SetDescriptions(d.LNTitles, d.Abbreviations)
			testDescsOK = true
		}
	}
	os.Exit(m.Run())
}

// needNSD skips a test that needs IEC's name space definitions when they
// are not available.
func needNSD(t testing.TB) {
	t.Helper()
	if testNSDErr != nil {
		t.Skip(testNSDErr)
	}
}
