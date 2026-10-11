// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mms

import (
	"crypto/x509"
	"net"
	"strings"
)

// Permission is a set of the pre-defined permissions of IEC 62351-8
// 6.2.1.2 Table 1, which a server maps its services to. The bits are in
// the table's order.
type Permission uint16

// The permissions of IEC 62351-8 Table 1.
const (
	PermListObjects Permission = 1 << iota
	PermReadValues
	PermDataSet
	PermReporting
	PermFileRead
	PermFileWrite
	PermFileMgt
	PermControl
	PermConfig
	PermSettingGroup
	PermSecurity
)

var permNames = []struct {
	p Permission
	n string
}{
	{PermListObjects, "LISTOBJECTS"}, {PermReadValues, "READVALUES"}, {PermDataSet, "DATASET"}, {PermReporting, "REPORTING"},
	{PermFileRead, "FILEREAD"}, {PermFileWrite, "FILEWRITE"}, {PermFileMgt, "FILEMGT"}, {PermControl, "CONTROL"},
	{PermConfig, "CONFIG"}, {PermSettingGroup, "SETTINGGROUP"}, {PermSecurity, "SECURITY"},
}

// String lists the permissions by their Table 1 names, "|" between them.
func (p Permission) String() string {
	var out []string
	for _, x := range permNames {
		if p&x.p != 0 {
			out = append(out, x.n)
		}
	}
	return strings.Join(out, "|")
}

// AccessControl decides what an association may do on a server, for
// example by the IEC 62351-8 roles in the peer's certificate; the
// application implements it (role verification is not part of this
// module).
type AccessControl interface {
	// Session is called once per association, after it is accepted, with
	// its connection (a TLS connection exposes its peer certificates) and
	// the certificate ACSE authentication verified (nil without).
	Session(nc net.Conn, acse *x509.Certificate) AccessSession
}

// AccessSession holds one association's rights.
type AccessSession interface {
	// Allows reports whether the association holds the permissions p.
	Allows(p Permission) bool
}
