// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850"
	"github.com/cB-Sigma/iec61850/mms"
)

// reports collects the parsed reports a client receives.
type reports struct {
	mu   sync.Mutex
	got  []iec61850.ParsedReport
	errs []error
}

func collectReports(cl *iec61850.Client) *reports {
	r := &reports{}
	go func() {
		for ir := range cl.Reports() {
			rep, err := iec61850.ParseReport(ir)
			r.mu.Lock()
			if err != nil {
				r.errs = append(r.errs, err)
			} else {
				r.got = append(r.got, rep)
			}
			r.mu.Unlock()
		}
	}()
	return r
}

// wait returns the first report received from now on (or already held
// after index from) that satisfies ok.
func (r *reports) wait(t *testing.T, from int, within time.Duration, what string, ok func(iec61850.ParsedReport) bool) (iec61850.ParsedReport, int) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		r.mu.Lock()
		for i := from; i < len(r.got); i++ {
			if ok(r.got[i]) {
				rep := r.got[i]
				r.mu.Unlock()
				return rep, i + 1
			}
		}
		n, errs := len(r.got), append([]error(nil), r.errs...)
		r.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("no report %s within %s (%d reports, parse errors %v)", what, within, n, errs)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (r *reports) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

func ref(t *testing.T, s, fc string) iec61850.Ref {
	t.Helper()
	r, err := iec61850.ParseRef(s, fc)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func readBool(t *testing.T, cl *iec61850.Client, s string) bool {
	t.Helper()
	d, err := cl.MMS().ReadOne(ctxT(t), ref(t, s, "").MMS())
	if err != nil {
		t.Fatalf("reading %s: %v", s, err)
	}
	if d.Kind != mms.KBool {
		t.Fatalf("%s is %v, not a boolean", s, d.Kind)
	}
	return d.Bool
}

func hasReason(e iec61850.ReportEntry, reason string) bool { return slices.Contains(e.Reasons, reason) }

const basicLD = "simpleIOGenericIO"

// TestBasicIO: association, discovery, reads, writes, data sets, a direct
// control and buffered and unbuffered reports against libiec61850's
// server_example_basic_io.
func TestBasicIO(t *testing.T) {
	cl, _, addr := startServer(t, "server_example_basic_io")
	rep := collectReports(cl)

	t.Run("association", func(t *testing.T) {
		id, err := cl.MMS().Identify(ctxT(t))
		if err != nil {
			t.Fatal(err)
		}
		if id.Vendor != "MZ" || id.Model != "basic io" {
			t.Errorf("identify: %+v", id)
		}
		if _, err := cl.MMS().Status(ctxT(t), false); err != nil {
			t.Errorf("status: %v", err)
		}
		t.Logf("negotiated: %+v", cl.MMS().Negotiated())
	})

	t.Run("discovery", func(t *testing.T) {
		lds, err := cl.LogicalDevices(ctxT(t))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(lds, basicLD) {
			t.Fatalf("logical devices %v", lds)
		}
		m, err := cl.Discover(ctxT(t), basicLD)
		if err != nil {
			t.Fatal(err)
		}
		for _, ln := range []string{"LLN0", "LPHD1", "GGIO1"} {
			if m.LogicalNodes[ln] == nil {
				t.Errorf("logical node %s missing: %v", ln, m.LogicalNodes)
			}
		}
		if !slices.Contains(m.LogicalNodes["GGIO1"]["MX"], "AnIn1") || !slices.Contains(m.LogicalNodes["GGIO1"]["CO"], "SPCSO1") {
			t.Errorf("GGIO1: %v", m.LogicalNodes["GGIO1"])
		}
		want := []string{"LLN0$MX$AnIn1$mag$f", "GGIO1$MX$AnIn1$mag$f", "GGIO1$MX$AnIn1$q"}
		got := strings.Join(m.DataSets["LLN0$Measurements"], " ")
		for _, w := range want[1:] {
			if !strings.Contains(got, w) {
				t.Errorf("data set Measurements %v lacks %s", m.DataSets["LLN0$Measurements"], w)
			}
		}
		for _, rcb := range []string{"LLN0.RP.EventsRCB01", "LLN0.BR.EventsBRCB01"} {
			if !slices.Contains(m.Reports, rcb) {
				t.Errorf("report control block %s not in %v", rcb, m.Reports)
			}
		}
		attrs, err := cl.Attributes(ctxT(t), basicLD, "GGIO1")
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(attrs, func(a iec61850.Attribute) bool {
			return a.Ref.FC == "CF" && strings.Join(a.Ref.Path, ".") == "SPCSO1.ctlModel"
		}) {
			t.Errorf("GGIO1 attributes lack SPCSO1.ctlModel[CF]: %d attributes", len(attrs))
		}
	})

	t.Run("read", func(t *testing.T) {
		d, err := cl.MMS().ReadOne(ctxT(t), ref(t, basicLD+"/GGIO1.AnIn1.mag.f", "MX").MMS())
		if err != nil || d.Kind != mms.KFloat || d.Float < -1.0001 || d.Float > 1.0001 {
			t.Errorf("AnIn1.mag.f: %+v %v", d, err)
		}
		typ, all, err := cl.AllDataValues(ctxT(t), basicLD, "GGIO1", "MX")
		if err != nil {
			t.Fatal(err)
		}
		v := iec61850.ToJSON(&typ, all, "")
		s := fmt.Sprint(v)
		if !strings.Contains(s, "AnIn4") {
			t.Errorf("GetAllDataValues MX: %s", s)
		}
		d, err = cl.MMS().ReadOne(ctxT(t), ref(t, basicLD+"/LLN0.NamPlt.vendor", "DC").MMS())
		if err != nil || d.Str != "MZ Automation" {
			t.Errorf("NamPlt.vendor: %+v %v", d, err)
		}
		d, err = cl.MMS().ReadOne(ctxT(t), ref(t, basicLD+"/GGIO1.SPCSO1.ctlModel", "CF").MMS())
		if err != nil || (d.Int != 1 && d.Uint != 1) {
			t.Errorf("ctlModel: %+v %v", d, err)
		}
		// An object that does not exist.
		if _, err := cl.MMS().ReadOne(ctxT(t), mms.DomainName(basicLD, "GGIO1$MX$NoSuch")); err == nil {
			t.Error("reading an unknown variable succeeded")
		}
	})

	t.Run("write", func(t *testing.T) {
		n := ref(t, basicLD+"/LLN0.NamPlt.vendor", "DC").MMS()
		if err := cl.MMS().WriteOne(ctxT(t), n, mms.Visible("SigmaM2M interop")); err != nil {
			t.Fatal(err)
		}
		d, err := cl.MMS().ReadOne(ctxT(t), n)
		if err != nil || d.Str != "SigmaM2M interop" {
			t.Errorf("after write: %+v %v", d, err)
		}
		// A measured value is read-only (FC MX).
		err = cl.MMS().WriteOne(ctxT(t), ref(t, basicLD+"/GGIO1.AnIn1.mag.f", "MX").MMS(), mms.Float32(5))
		if err == nil {
			t.Error("writing MX succeeded")
		}
	})

	t.Run("data sets", func(t *testing.T) {
		vals, err := cl.DataSetValues(ctxT(t), basicLD+"/LLN0$Events")
		if err != nil || len(vals) != 4 {
			t.Fatalf("Events values: %v %v", vals, err)
		}
		for _, v := range vals {
			if v.Err != nil || v.Data.Kind != mms.KBool {
				t.Errorf("Events member: %+v", v)
			}
		}
		members := []mms.ObjectName{
			ref(t, basicLD+"/GGIO1.AnIn1.mag.f", "MX").MMS(),
			ref(t, basicLD+"/GGIO1.SPCSO1.stVal", "ST").MMS(),
		}
		ds := basicLD + "/LLN0$SigmaDS"
		if err := cl.DefineDataSet(ctxT(t), ref(t, basicLD+"/LLN0.EventsRCB01", "RP"), ds, members); err != nil {
			t.Fatal(err)
		}
		got, err := cl.DataSetMembers(ctxT(t), ds)
		if err != nil || len(got) != 2 || got[1].String() != members[1].String() {
			t.Errorf("members %v %v", got, err)
		}
		vals, err = cl.DataSetValues(ctxT(t), ds)
		if err != nil || len(vals) != 2 || vals[0].Data.Kind != mms.KFloat {
			t.Errorf("values %+v %v", vals, err)
		}
		// Association-specific (non-persistent) data set.
		if err := cl.DefineDataSet(ctxT(t), ref(t, basicLD+"/LLN0.EventsRCB01", "RP"), "@SigmaAA", members[:1]); err != nil {
			t.Errorf("non-persistent data set: %v", err)
		} else if vals, err := cl.DataSetValues(ctxT(t), "@SigmaAA"); err != nil || len(vals) != 1 {
			t.Errorf("non-persistent values %+v %v", vals, err)
		}
		if err := cl.DeleteDataSet(ctxT(t), ds); err != nil {
			t.Error(err)
		}
		if _, err := cl.DataSetMembers(ctxT(t), ds); err == nil {
			t.Error("the deleted data set is still there")
		}
		// A data set the IED configured cannot be deleted.
		if err := cl.DeleteDataSet(ctxT(t), basicLD+"/LLN0$Events"); err == nil {
			t.Error("deleting a configured data set succeeded")
		}
	})

	t.Run("direct control", func(t *testing.T) {
		do := ref(t, basicLD+"/GGIO1.SPCSO1", "")
		for _, v := range []bool{true, false, true} {
			if err := cl.Operate(ctxT(t), do, v, iec61850.ControlOptions{OrIdent: "sigma"}); err != nil {
				t.Fatal(err)
			}
			if got := readBool(t, cl, basicLD+"/GGIO1$ST$SPCSO1$stVal"); got != v {
				t.Errorf("stVal %v after operate %v", got, v)
			}
		}
		// Test mode: the example's handler refuses test commands. With
		// normal security libiec61850 answers the Oper write before it
		// runs the handler (its control state machine executes the
		// operate afterwards), so the refusal is not reported; the value
		// staying put shows the Test flag arrived.
		if err := cl.Operate(ctxT(t), do, false, iec61850.ControlOptions{Test: true}); err != nil {
			t.Logf("test-mode operate: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
		if !readBool(t, cl, basicLD+"/GGIO1$ST$SPCSO1$stVal") {
			t.Error("an operate in test mode changed the value; the example refuses test commands")
		}
	})

	t.Run("unbuffered report", func(t *testing.T) {
		rcb := ref(t, basicLD+"/LLN0.EventsRCB01", "RP")
		from := rep.count()
		err := cl.EnableReport(ctxT(t), rcb, iec61850.RCBOptions{DataSet: basicLD + "/LLN0$Events", TrgOps: []string{"dchg", "gi"}, GI: true, Reserve: true})
		if err != nil {
			t.Fatal(err)
		}
		gi, next := rep.wait(t, from, 5*time.Second, "GI on Events1", func(r iec61850.ParsedReport) bool {
			return r.RptID == "Events1" && len(r.Entries) == 4 && hasReason(r.Entries[0], "gi")
		})
		if gi.DataSet != basicLD+"/LLN0$Events" || gi.ConfRev == nil || *gi.ConfRev != 1 {
			t.Errorf("GI report header: %+v", gi)
		}
		if gi.Entries[0].Ref != basicLD+"/GGIO1$ST$SPCSO1$stVal" || !gi.Entries[0].Value.Bool {
			t.Errorf("GI entry 0: %+v", gi.Entries[0])
		}
		if err := cl.Operate(ctxT(t), ref(t, basicLD+"/GGIO1.SPCSO2", ""), true, iec61850.ControlOptions{}); err != nil {
			t.Fatal(err)
		}
		dchg, _ := rep.wait(t, next, 5*time.Second, "dchg of SPCSO2", func(r iec61850.ParsedReport) bool {
			return r.RptID == "Events1" && len(r.Entries) >= 1 && slices.ContainsFunc(r.Entries, func(e iec61850.ReportEntry) bool {
				return e.Index == 1 && hasReason(e, "dchg")
			})
		})
		for _, e := range dchg.Entries {
			if e.Index == 1 && !e.Value.Bool {
				t.Errorf("SPCSO2 in report: %+v", e)
			}
		}
		if gi.SeqNum == nil || dchg.SeqNum == nil || *dchg.SeqNum <= *gi.SeqNum {
			t.Errorf("SqNum did not advance: %v then %v", gi.SeqNum, dchg.SeqNum)
		}
		vals, err := cl.RCBValues(ctxT(t), rcb)
		if err != nil || !vals["RptEna"].Bool || vals["DatSet"].Str != basicLD+"/LLN0$Events" {
			t.Errorf("GetURCBValues: %v %v", vals, err)
		}
		if err := cl.MMS().WriteOne(ctxT(t), rcb.Child("RptEna").MMS(), mms.Boolean(false)); err != nil {
			t.Error(err)
		}
	})

	t.Run("buffered report with resume", func(t *testing.T) {
		rcb := ref(t, basicLD+"/LLN0.EventsBRCB01", "BR")
		from := rep.count()
		err := cl.EnableReport(ctxT(t), rcb, iec61850.RCBOptions{DataSet: basicLD + "/LLN0$Events", TrgOps: []string{"dchg", "gi"}, GI: true})
		if err != nil {
			t.Fatal(err)
		}
		_, next := rep.wait(t, from, 5*time.Second, "GI on Events2", func(r iec61850.ParsedReport) bool {
			return r.RptID == "Events2" && len(r.Entries) == 4 && len(r.EntryID) == 8
		})
		if err := cl.Operate(ctxT(t), ref(t, basicLD+"/GGIO1.SPCSO3", ""), true, iec61850.ControlOptions{}); err != nil {
			t.Fatal(err)
		}
		last, _ := rep.wait(t, next, 5*time.Second, "dchg of SPCSO3", func(r iec61850.ParsedReport) bool {
			return r.RptID == "Events2" && slices.ContainsFunc(r.Entries, func(e iec61850.ReportEntry) bool { return e.Index == 2 && hasReason(e, "dchg") })
		})
		// Leave without disabling: the BRCB keeps buffering for us.
		cl.Close(context.Background())

		// Another association changes SPCSO3 and SPCSO4 meanwhile.
		other, err := iec61850.Connect(context.Background(), addr, mms.DialOptions{Timeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		if err := other.Operate(ctxT(t), ref(t, basicLD+"/GGIO1.SPCSO3", ""), false, iec61850.ControlOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := other.Operate(ctxT(t), ref(t, basicLD+"/GGIO1.SPCSO4", ""), true, iec61850.ControlOptions{}); err != nil {
			t.Fatal(err)
		}
		other.Close(context.Background())
		time.Sleep(300 * time.Millisecond) // past BufTm (50 ms)

		again, err := iec61850.Connect(context.Background(), addr, mms.DialOptions{Timeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { again.Close(context.Background()) })
		rep2 := collectReports(again)
		if err := again.EnableReport(ctxT(t), rcb, iec61850.RCBOptions{EntryID: last.EntryID}); err != nil {
			t.Fatalf("resume after %x: %v", last.EntryID, err)
		}
		r3, n2 := rep2.wait(t, 0, 5*time.Second, "resumed SPCSO3 off", func(r iec61850.ParsedReport) bool {
			return r.RptID == "Events2" && slices.ContainsFunc(r.Entries, func(e iec61850.ReportEntry) bool { return e.Index == 2 && !e.Value.Bool })
		})
		if bytes.Equal(r3.EntryID, last.EntryID) {
			t.Errorf("the entry resumed after was sent again")
		}
		// Both changes may come in one report (BufTm 50 ms).
		rep2.wait(t, n2-1, 5*time.Second, "resumed SPCSO4 on", func(r iec61850.ParsedReport) bool {
			return r.RptID == "Events2" && slices.ContainsFunc(r.Entries, func(e iec61850.ReportEntry) bool { return e.Index == 3 && e.Value.Bool })
		})
		_ = again.MMS().WriteOne(ctxT(t), rcb.Child("RptEna").MMS(), mms.Boolean(false))
	})
}

// TestComplexArray: an array of CMV structures, a data set whose members
// select array elements and their components (alternate access), and a
// report on it, against libiec61850's server_example_complex_array.
func TestComplexArray(t *testing.T) {
	cl, _, _ := startServer(t, "server_example_complex_array")
	rep := collectReports(cl)
	const ld = "testComplexArray"
	har := ref(t, ld+"/MHAI1.HA.phsAHar", "MX")
	typ, err := cl.TypeOf(ctxT(t), har.MMS())
	if err != nil {
		t.Fatal(err)
	}
	if typ.Kind != mms.KArray || typ.Elements != 16 {
		t.Fatalf("phsAHar type %+v", typ)
	}
	d, err := cl.MMS().ReadOne(ctxT(t), har.MMS())
	if err != nil || d.Kind != mms.KArray || len(d.Elems) != 16 {
		t.Fatalf("phsAHar %+v %v", d, err)
	}
	j := fmt.Sprint(iec61850.ToJSON(&typ, d, ""))
	if !strings.Contains(j, "cVal") {
		t.Errorf("phsAHar as JSON: %s", j)
	}
	// One element by alternate access.
	spec := mms.VariableSpec{Vars: []mms.ObjectName{har.MMS()}, Alt: []mms.AlternateAccess{{{Kind: mms.AltIndex, Index: 3}}}}
	res, err := cl.MMS().Read(ctxT(t), spec)
	if err != nil || len(res) != 1 || res[0].Err != nil || res[0].Data.Kind != mms.KStructure {
		t.Fatalf("phsAHar(3): %+v %v", res, err)
	}
	if !bytes.Equal(res[0].Data.Encode(), d.Elems[3].Encode()) {
		// The value moves once a second; compare the structure only.
		if len(res[0].Data.Elems) != len(d.Elems[3].Elems) {
			t.Errorf("phsAHar(3) %+v, whole array element %+v", res[0].Data, d.Elems[3])
		}
	}
	ds, err := cl.MMS().GetNamedVariableListSpec(ctxT(t), mms.DomainName(ld, "MHAI1$TestMHAI"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ds.Vars) != 5 || len(ds.Alt) != 5 || len(ds.AltOf(0)) == 0 || ds.AltOf(0)[0].Index != 7 {
		t.Errorf("TestMHAI members %+v", ds)
	}
	vals, err := cl.DataSetValues(ctxT(t), ld+"/MHAI1$TestMHAI")
	if err != nil || len(vals) != 5 {
		t.Fatalf("TestMHAI values %+v %v", vals, err)
	}
	for i, v := range vals {
		if v.Err != nil {
			t.Errorf("member %d: %v", i, v.Err)
		}
	}
	if vals[4].Data.Kind != mms.KFloat {
		t.Errorf("phsAHar(11).cVal.mag.f is %+v", vals[4].Data)
	}
	rcb := ref(t, ld+"/MHAI1.MHAIRCB01", "RP")
	if err := cl.EnableReport(ctxT(t), rcb, iec61850.RCBOptions{TrgOps: []string{"dchg", "integrity"}, IntgPd: time.Second}); err != nil {
		t.Fatal(err)
	}
	r, _ := rep.wait(t, 0, 5*time.Second, "on TestMHAI", func(r iec61850.ParsedReport) bool { return r.RptID == "TestMHAI" && len(r.Entries) > 0 })
	t.Logf("report: %d entries, reasons %v", len(r.Entries), r.Entries[0].Reasons)
	_ = cl.MMS().WriteOne(ctxT(t), rcb.Child("RptEna").MMS(), mms.Boolean(false))
}

// TestControls: the four control models and refusals against
// libiec61850's server_example_control.
func TestControls(t *testing.T) {
	cl, _, addr := startServer(t, "server_example_control")
	op := func(do string, v bool, o iec61850.ControlOptions) error {
		return cl.Operate(ctxT(t), ref(t, basicLD+"/GGIO1."+do, ""), v, o)
	}
	cases := []struct {
		do    string
		model int
	}{{"SPCSO1", iec61850.DirectNormal}, {"SPCSO2", iec61850.SBONormal}, {"SPCSO3", iec61850.DirectEnhanced}, {"SPCSO4", iec61850.SBOEnhanced}}
	for _, c := range cases {
		t.Run(c.do, func(t *testing.T) {
			m, err := cl.ControlModel(ctxT(t), ref(t, basicLD+"/GGIO1."+c.do, ""))
			if err != nil || m != c.model {
				t.Fatalf("ctlModel %d %v, want %d", m, err, c.model)
			}
			for _, v := range []bool{true, false} {
				if err := op(c.do, v, iec61850.ControlOptions{OrIdent: "sigma", Termination: 5 * time.Second}); err != nil {
					t.Fatalf("operate %v: %v", v, err)
				}
				if got := readBool(t, cl, basicLD+"/GGIO1$ST$"+c.do+"$stVal"); got != v {
					t.Errorf("stVal %v after %v", got, v)
				}
			}
		})
	}
	t.Run("interlock check flag", func(t *testing.T) {
		if err := op("SPCSO4", true, iec61850.ControlOptions{InterlockCheck: true}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("select and cancel", func(t *testing.T) {
		do := ref(t, basicLD+"/GGIO1.SPCSO4", "")
		if err := cl.Select(ctxT(t), do, true, iec61850.ControlOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := cl.Cancel(ctxT(t), do, true, iec61850.ControlOptions{}); err != nil {
			t.Fatal(err)
		}
		// Operate without a selection: refused with object-not-selected.
		err := cl.MMS().WriteOne(ctxT(t), do.Child("Oper").MMS(), mms.Boolean(true))
		if err == nil {
			t.Error("a malformed Oper write succeeded")
		}
		d, _ := cl.MMS().ReadOne(ctxT(t), ref(t, basicLD+"/GGIO1.SPCSO2.SBO", "CO").MMS())
		if d.Str == "" {
			t.Errorf("SBO read: %+v", d)
		}
		if err := cl.Cancel(ctxT(t), ref(t, basicLD+"/GGIO1.SPCSO2", ""), false, iec61850.ControlOptions{}); err != nil {
			t.Errorf("cancel SBO normal: %v", err)
		}
	})
	t.Run("refused by the IED (negative termination)", func(t *testing.T) {
		// SPCSO9 (direct enhanced): the example's check accepts it, its
		// operate handler fails, so the IED ends the command negatively.
		err := op("SPCSO9", true, iec61850.ControlOptions{Termination: 5 * time.Second})
		var ce *iec61850.ControlError
		if !errors.As(err, &ce) {
			t.Fatalf("operate SPCSO9: %v, want a ControlError", err)
		}
		t.Logf("SPCSO9: %v", err)
		if ce.Step != "termination" {
			t.Errorf("step %q, want termination", ce.Step)
		}
	})
	t.Run("refused select (selected by another client)", func(t *testing.T) {
		do := ref(t, basicLD+"/GGIO1.SPCSO4", "")
		if err := cl.Select(ctxT(t), do, true, iec61850.ControlOptions{}); err != nil {
			t.Fatal(err)
		}
		other, err := iec61850.Connect(context.Background(), addr, mms.DialOptions{Timeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close(context.Background())
		err = other.Select(ctxT(t), do, true, iec61850.ControlOptions{})
		var ce *iec61850.ControlError
		if !errors.As(err, &ce) || ce.Step != "select" {
			t.Fatalf("second select: %v, want a refused select", err)
		}
		t.Logf("second select: %v", err)
		if ce.AddCause != 19 && ce.AddCause != 27 { // object-already-selected, locked-by-other-client
			t.Errorf("AddCause %d, want 19 or 27", ce.AddCause)
		}
		if err := cl.Cancel(ctxT(t), do, true, iec61850.ControlOptions{}); err != nil {
			t.Error(err)
		}
	})
}

// TestSettingGroups: SGCB read, select active, select edit, edit and
// confirm against libiec61850's server_example_setting_groups.
func TestSettingGroups(t *testing.T) {
	cl, _, _ := startServer(t, "server_example_setting_groups")
	const ld = "DEMOPROT"
	readF := func(fc string) float64 {
		t.Helper()
		d, err := cl.MMS().ReadOne(ctxT(t), ref(t, ld+"/PTOC1.StrVal.setMag.f", fc).MMS())
		if err != nil || d.Kind != mms.KFloat {
			t.Fatalf("StrVal[%s]: %+v %v", fc, d, err)
		}
		return d.Float
	}
	sg, err := cl.ReadSGCB(ctxT(t), ld)
	if err != nil {
		t.Fatal(err)
	}
	if sg.NumOfSG != 5 || sg.ActSG != 1 {
		t.Errorf("SGCB %+v", sg)
	}
	if v := readF("SG"); v != 1 {
		t.Errorf("active StrVal %v, want 1", v)
	}
	if err := cl.SelectActiveSG(ctxT(t), ld, 2); err != nil {
		t.Fatal(err)
	}
	if sg, _ := cl.ReadSGCB(ctxT(t), ld); sg.ActSG != 2 || sg.LActTm == "" {
		t.Errorf("after select active: %+v", sg)
	}
	if v := readF("SG"); v != 2 {
		t.Errorf("group 2 StrVal %v, want 2", v)
	}
	if err := cl.SelectEditSG(ctxT(t), ld, 3); err != nil {
		t.Fatal(err)
	}
	if v := readF("SE"); v != 3 {
		t.Errorf("edit StrVal %v, want 3", v)
	}
	if err := cl.MMS().WriteOne(ctxT(t), ref(t, ld+"/PTOC1.StrVal.setMag.f", "SE").MMS(), mms.Float32(4.5)); err != nil {
		t.Fatal(err)
	}
	if err := cl.ConfirmEditSGValues(ctxT(t), ld); err != nil {
		t.Fatal(err)
	}
	if err := cl.SelectActiveSG(ctxT(t), ld, 3); err != nil {
		t.Fatal(err)
	}
	if v := readF("SG"); v != 4.5 {
		t.Errorf("confirmed StrVal %v, want 4.5", v)
	}
	if err := cl.SelectActiveSG(ctxT(t), ld, 9); err == nil {
		t.Error("selecting group 9 of 5 succeeded")
	}
}

// TestLogs: LCB read, QueryLogByTime and QueryLogAfter against
// libiec61850's server_example_logging (SQLite log storage).
func TestLogs(t *testing.T) {
	cl, _, _ := startServer(t, "server_example_logging")
	m, err := cl.Discover(ctxT(t), basicLD)
	if err != nil {
		t.Fatal(err)
	}
	// Journals are named after their logical node and log: LLN0$EventLog.
	if !slices.Contains(m.Logs, "LLN0$EventLog") {
		t.Errorf("logs %v", m.Logs)
	}
	if !slices.Contains(m.ControlBlocks["LG"], "LLN0.LG.EventLog") {
		t.Errorf("log control blocks %v", m.ControlBlocks)
	}
	lcbRef := ref(t, basicLD+"/LLN0.EventLog", "LG")
	lcb, err := cl.ReadLCB(ctxT(t), lcbRef)
	if err != nil {
		t.Fatal(err)
	}
	if !lcb.LogEna || lcb.DatSet != basicLD+"/LLN0$Events" || lcb.LogRef != basicLD+"/LLN0$EventLog" {
		t.Errorf("LCB %+v", lcb)
	}
	// The example's access handler makes every LCB read-only.
	if err := cl.EnableLog(ctxT(t), lcbRef, "", []string{"dchg", "integrity"}, 0); err == nil {
		t.Error("writing the read-only LCB succeeded")
	}
	start := time.Now().Add(-2 * time.Second)
	for _, v := range []bool{true, false} {
		if err := cl.Operate(ctxT(t), ref(t, basicLD+"/GGIO1.SPCSO1", ""), v, iec61850.ControlOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	log := basicLD + "/LLN0$EventLog"
	var entries []iec61850.LogEntry
	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, err = cl.QueryLogByTime(ctxT(t), log, start, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range entries {
			for _, v := range e.Values {
				if v.Ref == basicLD+"/GGIO1$ST$SPCSO1$stVal" {
					n++
				}
			}
		}
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	var seen []bool
	for _, e := range entries {
		if len(e.EntryID) != 8 || e.Time.Before(start) {
			t.Errorf("entry %x at %s", e.EntryID, e.Time)
		}
		for _, v := range e.Values {
			if v.Ref == basicLD+"/GGIO1$ST$SPCSO1$stVal" {
				seen = append(seen, v.Value.Bool)
				if !slices.Contains(v.Reasons, "dchg") {
					t.Errorf("reasons %v", v.Reasons)
				}
			}
		}
	}
	if len(seen) < 2 || seen[len(seen)-2] != true || seen[len(seen)-1] != false {
		t.Fatalf("logged SPCSO1 values %v in %d entries", seen, len(entries))
	}
	all, err := cl.QueryLogByTime(ctxT(t), log, time.Time{}, time.Time{})
	if err != nil || len(all) < len(entries) {
		t.Fatalf("whole log: %d entries, %v", len(all), err)
	}
	// The example's start-up entry holds an INT32 123.
	found := false
	for _, e := range all {
		for _, v := range e.Values {
			if v.Value.Kind == mms.KInt && v.Value.Int == 123 {
				found = true
			}
		}
	}
	if !found {
		t.Error("the example's start-up entry (123) is not in the log")
	}
	after, err := cl.QueryLogAfter(ctxT(t), log, entries[0].Time, entries[0].EntryID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(entries)-1 && len(after) != len(entries) {
		t.Errorf("after the first entry: %d entries of %d", len(after), len(entries))
	}
	for _, e := range after {
		if bytes.Equal(e.EntryID, entries[0].EntryID) {
			t.Errorf("QueryLogAfter returned the entry it started after")
		}
	}
	lcb2, err := cl.ReadLCB(ctxT(t), lcbRef)
	if err == nil && (len(lcb2.NewEnt) == 0 || lcb2.NewEntrTm.IsZero()) {
		t.Errorf("LCB NewEnt/NewEntrTm not set: %+v", lcb2)
	}
}

// TestFiles: directory, get and delete against libiec61850's
// server_example_files (a file store mounted from a temporary directory).
func TestFiles(t *testing.T) {
	needDocker(t)
	dir := t.TempDir()
	big := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB, several FileReads
	files := map[string][]byte{"hello.txt": []byte("hello from sigma\n"), "IEDSERVER.BIN": {1, 2, 3}, "COMTRADE/rec1.cfg": big}
	for name, b := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:102", port), "-v", dir+":/work/vmd-filestore", image, "stdbuf", "-oL", "server_example_files")
	var cl *iec61850.Client
	var err error
	for i := 0; i < 100; i++ {
		if cl, err = iec61850.Connect(context.Background(), fmt.Sprintf("127.0.0.1:%d", port), mms.DialOptions{Timeout: 2 * time.Second}); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close(context.Background())

	list, err := cl.FileDirectory(ctxT(t), "")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]iec61850.FileEntry{}
	for _, e := range list {
		names[e.Name] = e
	}
	t.Logf("directory: %v", list)
	if e, ok := names["hello.txt"]; !ok || e.Size != uint64(len(files["hello.txt"])) || e.LastModified.IsZero() {
		t.Errorf("hello.txt entry %+v in %v", e, list)
	}
	sub, err := cl.FileDirectory(ctxT(t), "COMTRADE/")
	if err != nil {
		t.Fatal(err)
	}
	if len(sub) != 1 || !strings.HasSuffix(sub[0].Name, "rec1.cfg") || sub[0].Size != uint64(len(big)) {
		t.Errorf("COMTRADE/: %+v", sub)
	}
	b, fe, err := cl.GetFile(ctxT(t), "hello.txt", 0)
	if err != nil || !bytes.Equal(b, files["hello.txt"]) || fe.Size != uint64(len(b)) {
		t.Errorf("get hello.txt: %q %+v %v", b, fe, err)
	}
	b, _, err = cl.GetFile(ctxT(t), "COMTRADE/rec1.cfg", 0)
	if err != nil || !bytes.Equal(b, big) {
		t.Errorf("get rec1.cfg: %d octets, %v", len(b), err)
	}
	if _, _, err := cl.GetFile(ctxT(t), "COMTRADE/rec1.cfg", 1000); !errors.Is(err, iec61850.ErrFileTooLarge) {
		t.Errorf("limited get: %v", err)
	}
	if _, _, err := cl.GetFile(ctxT(t), "missing.txt", 0); err == nil {
		t.Error("getting a missing file succeeded")
	}
	if err := cl.DeleteFile(ctxT(t), "IEDSERVER.BIN"); err == nil {
		t.Error("deleting IEDSERVER.BIN succeeded; the example's handler refuses it")
	}
	if err := cl.DeleteFile(ctxT(t), "hello.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "hello.txt")); !os.IsNotExist(err) {
		t.Errorf("hello.txt still on disk: %v", err)
	}
}
