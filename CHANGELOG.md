# Changelog

## v0.1.0 (unreleased)

First public release.

- IEC's machine-readable files are no longer part of the module. The
  data model is built from IEC's NSD files loaded at run time
  (`model.LoadNSD`, `model.SetNSDJSON`); LN titles and abbreviation
  meanings come from `model.SetDescriptions`; SCL schema validation uses
  IEC's schema loaded with `scl.LoadSchema` or `scl.LoadSchemaFiles`.
  Before loading, `model.Default` returns `model.ErrNoNSD` and
  `scl.Validate` applies the clause rules with one warning; the SCL
  export writes the control service members and enumeration literals it
  needs from facts when the model is not loaded.
- New: GoCB and MSVCB services on the client (`GoCBValues`,
  `SetGoCBValues`, `EnableGoCB`, `MSVCBValues`, `SetMSVCBValues`).
- New: GOOSE subscriber supervision (`goose.Subscription`: control
  block, data set, ConfRev and entry checks, NdsCom, simulation, arrival
  classification, time allowed to live).
- New: raw Ethernet capture and send on Linux (`goose.OpenInterface`,
  `goose.OpenSendInterface`).
- Fixed (found against libiec61850): the FileDirectory response carries
  its entry list inside an explicit `[0]` (the old form is still read);
  QueryLogByTime always sends both ends of the range.
- The simulated IED and TASE.2 server, their commands and the tests that
  drive them moved to github.com/cB-Sigma/iec61850-sim.
