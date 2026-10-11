# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, in Go from the standards in the
table below, read in licensed copies (IEC, ISO) or as published (ITU-T,
IETF, NIST, W3C). No code was ported or copied from another
implementation. Tags, codes, octet layouts, bit positions, object names
and procedures are facts every implementation must use; the code around
them (Go types, goroutines and channels, error handling) is our own
design. No text of the standards is reproduced; comments cite clause,
table and annex numbers in our own words. IEC's machine-readable files
are not in this module (see "IEC material" below).

The code was first written inside SigmaM2M (from 2026-09-27) and moved
to this module on 2026-10-06; the simulators, their commands and the
tests that drive them moved to the separate module iec61850-sim on
2026-10-11. SigmaM2M's requirement rows (SIG-IPE-…, SIG-SEC-…, SIG-CMD-…)
name the clauses each behaviour follows; the tests claim them with
`// Covers:` lines, which mean nothing outside SigmaM2M's compliance
report.

Where a standard leaves an encoding or a reading open, or contradicts
itself, the choice made is recorded in SigmaM2M's findings register.
Code comments refer to its entries by number (F-500 to F-529, F-690 to
F-699, F-756, F-785 to F-790, F-800 to F-884, F-1030 to F-1085, F-1150 to
F-1163 and F-1560 to F-1572); each comment says the choice in our words,
so the register itself is not needed to read the code.

## Sources

| Area (packages, files) | Followed | Read for facts only (no code taken) |
|---|---|---|
| OSI stack (mms: osi.go) | RFC 1006 (TPKT), ISO 8073 / ITU-T X.224 class 0 (COTP), ISO 8327-1 (session kernel), ISO 8823-1 (presentation, normal mode), ISO 8650-1 (ACSE), ITU-T X.690 (BER) | none |
| MMS (mms: pdu.go, data.go, access.go, initiate.go, nvl.go, file.go, journal.go, event*.go) | ISO 9506-1:2003 and ISO 9506-2:2003 | none |
| TLS for MMS (mms: tls.go, client.go) | IEC 62351-4:2018+AMD1:2020 clause 6 on top of IEC 62351-3:2023 (the profile itself is the application's, through iotsec) | none |
| ACSE authentication (mms: acseauth.go, identity.go) | IEC 62351-4 clause 11 and Annex A (A-security profile); RFC 8017 (RSASSA-PKCS1-v1_5) | IEC's ASN.1 modules for IEC 62351-4 (2018 and 2025-11), compared in tests that read them at run time, not copied |
| E2E security (mms: e2e.go, modp.go) | IEC 62351-4 clauses 12 to 15, Annexes B, D, G; RFC 5869 (HKDF), FIPS 202 and NIST SP 800-185 (SHA-3, KMAC), RFC 8702, RFC 3526 group 14, NIST SP 800-38A/D (CBC, GCM) | IEC's E2E-security ASN.1 module for IEC 62351-4 (2025-11), compared in tests, not copied |
| Access control seam (mms: accesscontrol.go) | IEC 62351-8:2020 Table 1 permissions; the service mappings are ours (F-1560, F-884) | none |
| ACSI client (root package: client.go, control.go, values.go, logs.go, files.go, sgcb.go) | IEC 61850-7-2 Ed. 2.1 and IEC 61850-8-1 Ed. 2.1 (mapping to MMS) | libiec61850's public API documentation (the client control group page, 2026-10-05) was read for how another client exposes the interlock and synchrocheck flags; it states no default, and the defaults in DefaultChecks are our own decision. No code was read or taken |
| Data model (model) | IEC 61850-7-2, -7-3, -7-4 Ed. 2.1, IEC 61850-8-1 (control services), IEC TR 61850-7-6:2024 (BAP) | IEC's NSD and ASD files, read at run time (nsdfiles.go is our own reader); data/text.yaml and data/bap.yaml hold facts and our own words |
| SCL (scl) | IEC 61850-6 Ed. 2.2 (2024) clauses 7 to 9 and Annexes C, F, G, I | IEC's SCL schema, loaded at run time and interpreted by github.com/cB-Sigma/xsd |
| GOOSE and SV (goose, goose/sv) | IEC 61850-8-1 clause 18 and Annexes A, C, J; IEC 61850-9-2 Ed. 2.1 and the 9-2 LE profile; IEC 62439-3 (HSR, PRP); IEC 62351-6:2020; RFC 2104, NIST SP 800-38D | none |
| TASE.2 (tase2) | IEC 60870-6-503:2014, -702:2014 (Annex A PICS), -802:2014; ISO 9506 event management | none |

## IEC material

IEC publishes machine-readable files for IEC 61850 and IEC 62351 under
its own licence. None of them, and nothing generated from them, is in
this module. What SigmaM2M kept in the library before publication and
what was done with each file (2026-10-11):

| File (before) | What it was | Choice |
|---|---|---|
| a generated `nsd_gen.go` | the NSD of IEC 61850-7-2, -7-3, -7-4, the 8-1 SNSD and the IEC TR 61850-7-6 ASD templates, rendered as JSON | moved out (stays in SigmaM2M); the library loads IEC's files at run time: `model.LoadNSD` (our own reader of IEC's NSD, SNSD, AppNS and ASD files) or `model.SetNSDJSON`; without them `model.Default` returns `ErrNoNSD` |
| a generated `xsd_gen.go` | the IEC 61850-6 SCL schema documents | moved out (stays in SigmaM2M); the user loads the schema at run time with `scl.LoadSchema` or `scl.LoadSchemaFiles`; without it `scl.Validate` applies the clause rules and says in one warning that schema checks were skipped |
| the LICENSE, NOTICE and doc.go of that generated package | IEC's licence and attributions for the two files above | moved out with them |
| `model/data/text.yaml`, keys `lnTitles` and `abbreviations` | LN class titles and the meanings of the 7-4 abbreviations, read from the licensed text | moved out (stays in SigmaM2M); the application passes them with `model.SetDescriptions`; without them titles are empty and descriptions use the names |
| `scl/testdata/ssd_9_2_8.ssd` | a file of IEC's SCL schema zip | moved out; the test reads it from `IEC61850_SCL_TESTDATA` and is skipped without it |
| `scl/testdata/clause9.scd`, `coordinates_annex_c.scd`, `NOTICE` | test systems built around example fragments of the IEC 61850-6 text | moved out, read the same way; replaced for the public tests by our own test system `scl/testdata/bay.scd` (`TestOwnSystem`, `TestLosslessRoundTrip`, `TestValidateWithoutSchema`) |
| `scl/export.go` (enumeration literals and control service members taken from the model) | names and values from the NSD when loaded | replaced, when the model is not loaded, by the same facts written out (`fallbackEnums`, `controlFields`); `TestExportFallbacksMatchModel` checks them against IEC's files when present |

Tests that compare our code with IEC's files read them from the
directories in `IEC61850_CODE_COMPONENTS` (IEC's unpacked zips),
`IEC61850_DESCRIPTIONS` and `IEC61850_SCL_TESTDATA`, and are skipped when
those are not set. SigmaM2M sets them in its own test runs, so every
such test runs there.

## Other implementations

libiec61850 (C, GPLv3 or commercial, MZ Automation), its TASE.2 library,
IEC61850bean/OpenMUC (Java, Apache-2.0) and the Wireshark dissectors are
the best-known other implementations. None was used as a source: no code
was ported or copied. libiec61850's public API documentation was
consulted once, for the control flags noted in the table, and its source
was read only to diagnose interop results (below). I searched
this module for their characteristic identifiers (IedConnection,
MmsValue, IsoConnection, CotpConnection, IsoPresentation, GoosePublisher,
SVPublisher, ClientReportControlBlock, LinkedList_, ByteBuffer,
iec61850bean) and for porting or attribution comments, and found none.

libiec61850 (GPLv3) is a test peer only. `interop/peer/Dockerfile`
clones it at tag v1.6.2.1 (commit 6e7a603c771d6124cd3cafea7ec38b7e0f2e7aaf)
and builds it inside the container image; it is not vendored, not
copied into this tree, and not distributed. Its SCL example files are
read from the container at test time. `interop/peer/gspeer.c` is our own
small program written against libiec61850's public API (so it uses
names such as GoosePublisher and LinkedList_, which the identifier search
above does not count). While diagnosing the interop results
(2026-10-11), parts of libiec61850's source were read to understand its
behaviour (its FileDirectory and ReadJournal encoders and parsers, its
control state machine and its LastApplError handling); no code was taken
from it, and each fix in this module follows the standard's ASN.1 or
clause, cited in the code.

## Defaults that name SigmaM2M

The SCL export (`scl.ExportGateway`) writes "SigmaM2M" as manufacturer
and tool ID when `Gateway.Manufacturer` and `Gateway.Tool` are empty; set
them to change it.
