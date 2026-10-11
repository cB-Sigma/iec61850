// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package testpki

import (
	"os"
	"path/filepath"
	"testing"
)

// SpecData is the path of a file or directory of IEC's machine-readable
// files (ASN.1 modules, SCL schema and examples), which this module does
// not carry, under $IEC61850_CODE_COMPONENTS (a directory holding IEC's
// unpacked zips). The test is skipped when it is not there. depth is no
// longer used; it is kept for the callers.
func SpecData(t testing.TB, depth int, rel string) string {
	t.Helper()
	_ = depth
	dir := os.Getenv("IEC61850_CODE_COMPONENTS")
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if dir == "" {
		t.Skipf("%s is not here (set IEC61850_CODE_COMPONENTS to a directory of IEC's unpacked files)", rel)
	}
	if _, err := os.Stat(p); err != nil {
		t.Skipf("%s is not here (set IEC61850_CODE_COMPONENTS to a directory of IEC's unpacked files)", rel)
	}
	return p
}
