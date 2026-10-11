// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package iec61850 is an IEC 61850 client (the ACSI services of IEC
// 61850-7-2 mapped onto MMS as IEC 61850-8-1 specifies) in pure Go: it
// associates with an IED over the MMS stack of package mms (optionally
// over TLS, with ACSE authentication or IEC 62351-4 E2E security),
// discovers logical devices, nodes, data sets and control blocks, reads
// and writes data attributes with their functional constraints, enables
// buffered and unbuffered reports (reassembling segmented ones, resuming
// after an EntryID), defines data sets, operates controls with the direct
// and select-before-operate models (normal and enhanced security, time
// activated operate, CommandTermination and LastApplError, the
// interlock and synchrocheck defaults of DefaultChecks), reads and
// switches setting groups, queries logs and reads and deletes files.
// Values convert to and from JSON-friendly Go values (ToJSON, FromJSON,
// QualityJSON).
//
// Related packages: model (the IEC 61850-7-x data model as data), scl
// (SCL parsing, validation, import and export), goose and goose/sv
// (GOOSE and sampled values frames, publishing and IEC 62351-6 security),
// sim (an in-process IED for tests and server roles), tase2 and
// tase2/sim (ICCP / TASE.2 on the same MMS stack).
package iec61850
