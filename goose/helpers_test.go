// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package goose

import (
	"strings"

	"github.com/cB-Sigma/iec61850"
	"github.com/cB-Sigma/iec61850/mms"
)

// dataJSON renders the members the tests look at as an application would:
// a quality as its JSON form, a 2-bit Dbpos by name.
func dataJSON(name string, v mms.Data) any {
	if v.Kind != mms.KBitString {
		return nil
	}
	if v.Bits.NBits == 13 || strings.HasSuffix(name, ".q") {
		return iec61850.QualityJSON(v.Bits)
	}
	if v.Bits.NBits == 2 {
		i := 0
		if v.Bits.Get(0) {
			i |= 2
		}
		if v.Bits.Get(1) {
			i |= 1
		}
		return [...]string{"intermediate", "off", "on", "bad"}[i]
	}
	return nil
}
