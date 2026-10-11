# iec61850

IEC 61850 in pure Go: an MMS client on its own OSI stack, the IEC 61850
client services mapped onto MMS, the data model, SCL, GOOSE and sampled
values with IEC 62351 security, and ICCP / TASE.2.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/iec61850.svg)](https://pkg.go.dev/github.com/cB-Sigma/iec61850) [![test](https://github.com/cB-Sigma/iec61850/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/iec61850/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.26.0-00ADD8.svg)](go.mod)

The module speaks MMS (ISO 9506) over TPKT, COTP, session, presentation
and ACSE, with TLS, ACSE certificate authentication and end-to-end
security of IEC 62351-4. On top of it sit the IEC 61850-8-1 client
services (discovery, data access, data sets, reports, controls, setting
groups, logs, files, GOOSE and sampled value control blocks), the
IEC 61850-7-x data model, SCL parsing, validation and export, GOOSE and
sampled value codecs and publishers (Layer 2, HSR/PRP, routable over
UDP) with IEC 62351-6 security, and the TASE.2 types and encodings. It
has no cgo. It was written for SigmaM2M, a oneM2M platform, where it
serves the IEC 61850, GOOSE and ICCP integrations.

**IEC's machine-readable files are not included.** The data model is
built from IEC's name space definition (NSD) files and SCL is validated
against IEC's SCL schema; IEC publishes both under its own licence, so
an application loads them at run time (`model.LoadNSD`, `scl.LoadSchema`)
from copies it obtained from IEC. Without them everything else works:
the client, the codecs, SCL parsing and the clause rules of IEC 61850-6;
`model.Default` returns `model.ErrNoNSD` and `scl.Validate` reports in
one warning that schema checks were skipped.

## Features

| Area | Status |
|---|---|
| OSI stack: TPKT (RFC 1006), COTP class 0 with segmentation, session kernel, presentation normal mode, ACSE (password, certificate and E2E authentication) | yes; other COTP classes and OSI over anything but TCP: no |
| MMS client: Initiate, Conclude, Abort, Identify, Status, GetNameList, GetVariableAccessAttributes, Read, Write (alternate access), named variable lists, InformationReport, event management (conditions, actions, enrollments, notifications, acknowledgement, alarm summaries), ReadJournal, files (directory, open, read, close, delete, obtain) | yes |
| MMS domain management (GetDomainAttributes and the rest), program invocation, semaphores, operator communication | not yet: IEC 61850-8-1 and TASE.2 conformance blocks 1 to 5 and 7 do not require them (logical devices are found with GetNameList); TASE.2 block 6 would need program invocation |
| MMS edge cases: Reject PDUs, Cancel, outstanding-request limit and PDU size from Initiate, the negotiated service list (`Client.Supports`) | Reject and the negotiated limits: yes; sending Cancel: not yet |
| Server-side association (`mms.ServerConn`, `mms.AccessControl` with IEC 62351-8 permissions) | yes; an IED is in [iec61850-sim](https://github.com/cB-Sigma/iec61850-sim) |
| IEC 61850 client: association, discovery (logical devices, nodes, data, data sets), reads and writes with functional constraints, JSON value conversion | yes |
| Data sets: define, delete, read members and values (persistent and association-specific) | yes |
| Reports: BRCB and URCB, segmented reports, EntryID resume, GI, integrity, reservation | yes |
| Controls: direct and select-before-operate, normal and enhanced security, time activated operate, cancel, originator (orCat, orIdent), the Test flag, interlock and synchrocheck Check bits with `DefaultChecks`, AddCause in errors | yes |
| Substitution (SubEna, SubVal, SubQ, SubID), Mod/Beh and test or simulation modes from the client | through ordinary reads and writes (no dedicated calls) |
| Editions: IEC 61850-8-1 Ed. 1, Ed. 2 and Ed. 2.1 IEDs (report control block naming and indexes, ResvTms and Owner, Ed. 1 RCBs without them, GoCB attributes) | yes; each behaviour follows the attributes the IED declares |
| Setting groups: read SGCB, select active, select edit, confirm | yes |
| Logs: LCB read and enable, QueryLogByTime, QueryLogAfter | yes |
| Files: directory, get, delete | yes; SetFile (the server fetching a file from the client) not yet: it needs the client to serve MMS file reads, which no IED we know of asks for |
| GOOSE and MSVCB control blocks over MMS: GetGoCBValues, SetGoCBValues, GetMSVCBValues, SetMSVCBValues | yes; USVCB (unicast SV) services: not yet, no IED we checked offers them |
| Service tracking (LTRK), GetGoReference and GetGOOSEElementNumber | not yet: optional in IEC 61850-8-1 and not offered by the IEDs we checked |
| Data model: CDCs, constructed attributes, enumerations, LN classes with inheritance, presence conditions, control services, object reference checks, descriptions and units, IEC TR 61850-7-6 Basic Application Profile checks | yes, from IEC's NSD files (the format of IEC 61850-7-7) loaded at run time |
| SCL (IEC 61850-6:2009+AMD1:2018+AMD2:2024, schema 2007C5): lossless tree, typed model, validation by the SCL schema and the clause rules, SSD, SCD, ICD, IID, CID and SED files, older SCL versions checked against their release with departures as warnings, Private and IEC 61850-6-100 application elements kept, GOOSE/SV publications and subscriptions, IID/CID export of a gateway | yes; schema validation needs IEC's SCL schema loaded; full SCL editing, conversion between SCL versions and SED exchange workflows: no |
| GOOSE codec: BER encoding, decoding of the fixed-length encoding (8-1 A.3), 802.1Q, the simulation bit, HSR and PRP tags (codec only: no redundancy node, duplicate discard or supervision frames) | yes; sending the fixed-length encoding: not yet (optional) |
| GOOSE publisher with the retransmission curve; subscriber supervision (`goose.Subscription`: control block, data set, ConfRev and entry checks, NdsCom, simulation, stNum/sqNum classification, time allowed to live) | yes |
| SV: IEC 61850-9-2 APDU codec with several ASDUs and smpSynch, decoding streams, a publisher with the UCA 9-2LE profile, per-window RMS, quality and frequency (`goose.Aggregator`) | yes; the IEC 61869-9 profile: partly (the sample counter options only) |
| Routable GOOSE and SV over UDP (IEC 61850-8-1:2011+AMD1:2020 and IEC 61850-9-2:2011+AMD1:2020, from IEC TR 61850-90-5), with TTL and DSCP | yes |
| IEC 62351-6 security: Layer 2 and routable, HMAC and GMAC authentication, AES-GCM (and CBC) payload encryption of routable messages, key store with GDOI delivery | yes |
| Other parts and mappings: IEC 61850-8-2 (XMPP), IEC 61850-90-2, IEC 62351-7 (network management objects), time synchronisation (SNTP, the IEC/IEEE 61850-9-3 PTP profile) | no: outside this module |
| Raw Ethernet capture and send (`goose.OpenInterface`, `goose.OpenSendInterface`) | Linux (AF_PACKET, CAP_NET_RAW); pcap replay and recording everywhere |
| TASE.2 (IEC 60870-6-503/-702/-802): the object types and their MMS encodings for conformance blocks 1, 2, 3, 4, 5 and 7, the version and Supported_Features objects, and a statement of what a client built on this module offers (`tase2.ClientCapabilities`); the client operations themselves (transfer sets, devices, acknowledgements) are MMS reads, writes and information reports through `mms.Client` | yes; blocks 6 (program control), 8 (additional user objects such as transfer accounts) and 9 (time series): not yet |

Security services come in through
[iotsec](https://github.com/cB-Sigma/iotsec):

| Need | Seam | Without it |
|---|---|---|
| IEC 62351-3 TLS profile | `iotsec.TLSClient` (`mms.DialOptions.Profile`), `iotsec.TLSServer`; `iotsec.StdTLS` wraps crypto/tls | `mms.DialOptions.TLS` (*tls.Config) or plain TCP |
| Idle-link keepalive before a timed key update | `iotsec.KeepaliveConn` (an MMS Identify, else Status) | none needed |
| Security events | `iotsec.Auditor` (`mms.SetAuditor`, `mms.AuthOptions.Auditor`) | slog only |
| Certificates for ACSE authentication and E2E | `mms.AuthIdentity` (an `iotsec.KeySource` plus a peer check) | `mms.StaticIdentity` (crypto/x509 path check, optional `iotsec.CertValidator` for revocation) |
| IEC 62351-8 roles on a server | `mms.AccessControl` | every service allowed |
| GOOSE/SV keys from a GDOI key server (IEC 62351-9) | `goose.KeyStore.Deliver` | static keys only |

[iec62351](https://github.com/cB-Sigma/iec62351) implements the TLS
profile, revocation, key management and roles behind these seams.

## Choosing an IEC 61850 library

Compared from each project's documentation in October 2026. Check the
projects themselves before relying on a row.

| | this module | libiec61850 | IEC61850bean (beanit) | otfabric/go-iec61850 |
|---|---|---|---|---|
| Language | Go, no cgo | C (bindings for C#/.NET; experimental Python) | Java | Go |
| Licence | Apache-2.0 | GPLv3, or commercial from MZ Automation | Apache-2.0 | MIT |
| MMS client | yes | yes | yes | yes |
| MMS server (IED) | server-side association here; an in-process IED in iec61850-sim | yes, full | yes | yes (per its documentation) |
| GOOSE / SV | publish and subscribe, subscriber supervision, routable, IEC 62351-6 authentication and encryption | publish and subscribe; R-GOOSE/R-SMV (beta in 1.6) | no | not stated |
| IEC 62351-3/-4 | TLS, ACSE certificate authentication, E2E security | TLS (IEC 62351-3/-4 per its documentation), ACSE password | no | not stated |
| SCL | parse, validate (with IEC's schema), export | parse (code and configuration generators, SCLParser) | parse | parse, validate, generate |
| TASE.2 | types, encodings, client capabilities; a server in iec61850-sim | separate commercial library | no | no |

There are also Go wrappers of libiec61850 through cgo (they inherit its
GPL licence). Pick this module for a Go program without cgo that needs
GOOSE or sampled values, IEC 62351 security on MMS and GOOSE, or TASE.2,
or when GPL is not an option. Pick libiec61850 for a C code base, for an
embedded IED with a mature server, or when you can buy its commercial
licence. Pick IEC61850bean for a Java client without GOOSE, and
go-iec61850 for a pure-Go MMS client and server without GOOSE or
IEC 62351 when its MIT licence suits you better. The other projects are
named for comparison only; this module is not affiliated with them.

## Install

```
go get github.com/cB-Sigma/iec61850@latest
```

Requires Go 1.26.0 or later.

## Quick start

```go
import (
	"github.com/cB-Sigma/iec61850"
	"github.com/cB-Sigma/iec61850/mms"
)

cl, err := iec61850.Connect(ctx, "192.0.2.5:102", mms.DialOptions{Timeout: 5 * time.Second})
if err != nil {
	return err
}
defer cl.Close(ctx)
lds, _ := cl.LogicalDevices(ctx)
m, _ := cl.Discover(ctx, lds[0]) // m.LogicalNodes: LN → FC → data objects
pos, _ := iec61850.ParseRef(lds[0]+"/CSWI1.Pos", "CO")
i, s := iec61850.DefaultChecks(pos.String())
err = cl.Operate(ctx, pos, true, iec61850.ControlOptions{InterlockCheck: i, SynchroCheck: s})
```

The data model and SCL schema validation, with IEC's files unpacked
into a directory:

```go
err := model.LoadNSD(os.DirFS("iec-files"))            // NSD, SNSD and ASD zips, unpacked
err = scl.LoadSchema(os.DirFS("iec-files/IEC_61850-6.SCL.2007C5"))
doc, _ := scl.Parse(raw)
issues := scl.Validate(doc, scl.Options{})
```

Runnable examples: `ExampleParseRef` and `ExampleDefaultChecks` (root),
`scl.ExampleParse`, `goose.ExampleDecode`, `model.Example` (compiled;
it needs IEC's files to run). iec61850-sim has examples against its
simulated IED and TASE.2 server.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/iec61850

| Package | What it does |
|---|---|
| `iec61850` (module root) | IEC 61850 client: `Connect`, discovery, reads and writes, data sets, reports, controls, setting groups, logs, files, GoCB and MSVCB services; JSON value conversion |
| `mms` | MMS (ISO 9506) over the OSI stack; TLS (`DialOptions.Profile`, `CheckTLSParams`), ACSE certificate authentication (`CertAuth`, `AuthIdentity`, `StaticIdentity`), IEC 62351-4 E2E security (`E2E`), the server-side association and access control seam |
| `model` | The IEC 61850-7-2/-7-3/-7-4 model built from IEC's NSD files (`LoadNSD`, `SetNSDJSON`, `SetDescriptions`), object reference checks, descriptions and units, IEC TR 61850-7-6 Basic Application Profile checks |
| `scl` | SCL parsing with a lossless tree, validation (`LoadSchema` for IEC's schema, plus the clause rules), the typed model, GOOSE/SV publications and subscriptions, IID/CID export |
| `goose` | GOOSE and SV frames (802.1Q, HSR, PRP), the GOOSE publisher, SV streams, routable GOOSE/SV over UDP, IEC 62351-6 keys and security, `Source`/`Sink` with pcap and Linux raw Ethernet |
| `goose/sv` | IEC 61850-9-2 sampled values: APDU codec, control blocks, a publisher |
| `tase2` | ICCP / TASE.2 types and encodings, conformance blocks, client capabilities |
| `interop` (nested module, tests only) | this module against libiec61850 in Docker |

## Testing

```
go vet ./...
go test -race ./...
```

Tests that compare this module with IEC's machine-readable files (NSD,
SCL schema, IEC 62351-4 ASN.1 modules) or with SCL files built around
the standard's examples read them from the directories named by
`IEC61850_CODE_COMPONENTS` (IEC's unpacked zips side by side),
`IEC61850_DESCRIPTIONS` (LN titles and abbreviation meanings, YAML) and
`IEC61850_SCL_TESTDATA`, and are skipped when these are not set. None of
these files is in this repository: IEC's come from IEC under its licence,
and the titles, meanings and example-based SCL files are the tester's
own. Without
them the model tests mostly skip; the rest of the module is tested on
its own data.

Tests carry `// Covers: SIG-...` comments: these are requirement IDs of
the SigmaM2M project's compliance report and have no meaning outside it.
Code comments that cite `F-` numbers refer to SigmaM2M's register of
readings where the standard leaves a choice open; PROVENANCE.md explains
them. The tests that drive the simulated IED and TASE.2 server are in
[iec61850-sim](https://github.com/cB-Sigma/iec61850-sim), so this module
does not depend on its simulators.

## Interop tested against

**libiec61850 v1.6.2.1** (MZ Automation, GPLv3, commit `6e7a603c`), a
test peer only: built from source in Docker by the nested module
`interop/` (and `iec61850-sim/interop` for the simulator), never vendored.
Run with `SIGMA_IEC61850_INTEROP=1 go test ./...` in `interop/`; the
tests skip without Docker. Results of 2026-10-11:

| Service | Against | Result |
|---|---|---|
| Association, Identify, Status, discovery (LDs, LNs, data sets, RCBs, LCBs, logs) | `server_example_basic_io`, `_logging` | pass |
| Read, write (DC, refused MX), GetAllDataValues, arrays and alternate access | `_basic_io`, `_complex_array` | pass |
| Data sets: read, define (persistent and `@`), delete, refused delete | `_basic_io` | pass |
| Unbuffered and buffered reports, GI, dchg, EntryID resume after reconnect | `_basic_io`, `_complex_array` | pass |
| Controls: direct and SBO, normal and enhanced, interlock flag, cancel, negative CommandTermination, select refused while another client holds it | `server_example_control` | pass |
| Setting groups: SGCB read, select active, select edit, edit SE, confirm, refused group | `server_example_setting_groups` | pass |
| Logs: LCB read, refused LCB write, QueryLogByTime, QueryLogAfter | `server_example_logging` (SQLite) | pass |
| Files: directory, subdirectory, get (64 KiB), size limit, delete, refused delete | `server_example_files` | pass |
| GoCB over MMS: read, GoEna on and off, published GOOSE checked | `server_example_goose` | pass |
| GOOSE: their publisher to `goose.Decode`, `goose.Publisher` to their subscriber (stNum, sqNum, TAL, values, quality) | `goose_publisher_example`, `goose_subscriber_example`, own program on their API | pass |
| SV: their publisher to `goose.Decode`, `sv.Publisher` to their subscriber (svID, smpCnt, FLOAT32, INT32, quality) | `sv_publisher_example`, `sv_subscriber_example`, own program on their API | pass |
| SCL: parse, model expansion and clause rules on all 46 SCL files of the release (XSD too when `IEC61850_CODE_COMPONENTS` or `SIGMA_SCL_SCHEMA_DIR` is set) | examples, demos, tools | pass |

Fixed on the way (each with a unit test): the FileDirectory response's
`listOfDirectoryEntry` is an explicitly tagged `[0]` around the SEQUENCE
OF (we sent and expected the entries directly in `[0]`; the old form is
still accepted), and QueryLogByTime now always sends both range ends
(libiec61850 rejects a start without a stop).

libiec61850 behaviour noted, not bent around: with normal security it
answers the Oper write before its handler runs, so a handler's refusal
(such as a Test command) is not reported; its own example SCL
`sg_demo.cid` has duplicate DOType ids and a missing DAType, which the
validator reports. Not tested: SetFile (the client has no file server
side for ObtainFile), TLS and ACSE authentication, routable GOOSE/SV.

No other IED, control centre or TASE.2 peer has been tested; no open
TASE.2 server exists to test `tase2` against.

## Related repositories

- [iec61850-sim](https://github.com/cB-Sigma/iec61850-sim): a simulated
  IED (MMS server) and a TASE.2 server, as Go packages and commands.
- [iec62351](https://github.com/cB-Sigma/iec62351): the IEC 62351
  security services behind the seams.
- [iotsec](https://github.com/cB-Sigma/iotsec): the security seams.
- [xsd](https://github.com/cB-Sigma/xsd): the XML Schema validator used
  for SCL.

## Status

v0.x: the API may change before v1. Not certified; no conformance claim.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam. IEC is a trademark of the International Electrotechnical
Commission and UCA a trademark of the UCA International Users Group;
other names are trademarks of their owners. This module is not
affiliated with or endorsed by any of them.
