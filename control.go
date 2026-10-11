package iec61850

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
	iecmodel "github.com/cB-Sigma/iec61850/model"
)

// Control models (values of ctlModel, IEC 61850-7-2 control model).
const (
	StatusOnly     = 0
	DirectNormal   = 1
	SBONormal      = 2
	DirectEnhanced = 3
	SBOEnhanced    = 4
)

var modelNames = []string{"status-only", "direct-with-normal-security", "sbo-with-normal-security",
	"direct-with-enhanced-security", "sbo-with-enhanced-security"}

// AddCause values of LastApplError (IEC 61850-7-2, by number).
var addCauses = map[int]string{
	0: "unknown", 1: "not-supported", 2: "blocked-by-switching-hierarchy", 3: "select-failed",
	4: "invalid-position", 5: "position-reached", 6: "parameter-change-in-execution", 7: "step-limit",
	8: "blocked-by-mode", 9: "blocked-by-process", 10: "blocked-by-interlocking",
	11: "blocked-by-synchrocheck", 12: "command-already-in-execution", 13: "blocked-by-health",
	14: "1-of-n-control", 15: "abortion-by-cancel", 16: "time-limit-over", 17: "abortion-by-trip",
	18: "object-not-selected", 19: "object-already-selected", 20: "no-access-authority",
	21: "ended-with-overshoot", 22: "abortion-due-to-deviation", 23: "abortion-by-communication-loss",
	24: "blocked-by-command", 25: "none", 26: "inconsistent-parameters", 27: "locked-by-other-client",
}

// applErrors are the Error values of LastApplError (IEC 61850-8-1 20.11).
var applErrors = []string{"no-error", "unknown", "timeout-test-not-ok", "operator-test-not-ok"}

// ControlError is a refused or failed control, with the IED's AddCause
// (and LastApplError Error) when it sent one.
type ControlError struct {
	Object   string
	Step     string // "select", "operate", "cancel", "termination"
	AddCause int    // -1 when unknown
	// ApplError is the LastApplError Error value (0 no error, 1 unknown,
	// 2 timeout test not ok, 3 operator test not ok).
	ApplError int
	Err       error
}

// Error describes the failure.
func (e *ControlError) Error() string {
	msg := fmt.Sprintf("%s of %s failed", e.Step, e.Object)
	if e.AddCause >= 0 {
		name := addCauses[e.AddCause]
		if name == "" {
			name = "cause"
		}
		msg += fmt.Sprintf(": %s (AddCause %d)", name, e.AddCause)
		if e.ApplError > 0 && e.ApplError < len(applErrors) {
			msg += ", " + applErrors[e.ApplError]
		}
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the underlying error.
func (e *ControlError) Unwrap() error { return e.Err }

// ControlOptions are the per-operation control parameters.
type ControlOptions struct {
	OrCat          int    // originator category (default 3, remote control)
	OrIdent        string // originator identification
	Test           bool
	InterlockCheck bool
	SynchroCheck   bool
	// Termination bounds the wait for CommandTermination (enhanced
	// security; default 10s), counted from OperTm when that is later.
	Termination time.Duration
	// OperTm, when set, asks for a time activated operation: the IED
	// executes the operate at this time (sent in operTm; zero means now).
	OperTm time.Time
}

type ctlEvent struct {
	addCause  int  // LastApplError AddCause, -1 for none
	applError int  // LastApplError Error
	ctlNum    int  // LastApplError ctlNum, -1 when not known
	term      bool // a CommandTermination (positive when addCause < 0)
}

type ctlWaiter struct {
	ch  chan ctlEvent
	num int // ctlNum of the operation waiting
}

// mine reports whether an event belongs to the waiting operation: a
// LastApplError carries the operation's ctlNum (IEC 61850-8-1 20.11).
func (w *ctlWaiter) mine(ev ctlEvent) bool { return ev.ctlNum < 0 || ev.ctlNum == w.num }

// controlReport routes LastApplError and CommandTermination reports to
// the operation waiting for them.
func (cl *Client) controlReport(r mms.InformationReport) {
	var obj string
	ev := ctlEvent{addCause: -1, ctlNum: -1}
	for i, v := range r.Spec.Vars {
		if i >= len(r.Results) {
			break
		}
		switch {
		case v.Scope == mms.ScopeVMD && v.Item == "LastApplError":
			// CntrlObj, Error, Origin, ctlNum, AddCause (8-1 Table 109).
			d := r.Results[i].Data
			if d.Kind == mms.KStructure && len(d.Elems) >= 5 {
				obj = d.Elems[0].Str
				ev.applError, _ = asInt(d.Elems[1])
				if n, ok := asInt(d.Elems[3]); ok {
					ev.ctlNum = n
				}
				ev.addCause, _ = asInt(d.Elems[4])
			}
		case v.Scope == mms.ScopeDomain && strings.Contains(v.Item, "$CO$"):
			ev.term = true
			obj = v.Domain + "/" + v.Item
		}
	}
	key := controlKey(obj)
	if key == "" {
		return
	}
	cl.mu.Lock()
	w := cl.waiters[key]
	cl.mu.Unlock()
	if w != nil {
		select {
		case w.ch <- ev:
		default:
		}
	}
}

// controlKey reduces "LD/LN$CO$DO$Oper" to "LD/LN$CO$DO".
func controlKey(obj string) string {
	i := strings.LastIndexByte(obj, '$')
	if i < 0 || !strings.Contains(obj, "$CO$") {
		return ""
	}
	return obj[:i]
}

// ControlModel reads a controllable data object's ctlModel (CF).
func (cl *Client) ControlModel(ctx context.Context, do Ref) (int, error) {
	r := do
	r.FC = "CF"
	d, err := cl.c.ReadOne(ctx, r.Child("ctlModel").MMS())
	if err != nil {
		return 0, fmt.Errorf("reading the control model of %s: %w", do.String(), err)
	}
	switch d.Kind {
	case mms.KInt:
		return int(d.Int), nil
	case mms.KUint:
		return int(d.Uint), nil
	}
	return 0, fmt.Errorf("the control model of %s is not an integer", do.String())
}

// ctlStruct builds an Oper, SBOw or Cancel value for the structure type t.
func (cl *Client) ctlStruct(t mms.TypeSpec, value any, o ControlOptions, num uint8) (mms.Data, error) {
	if t.Kind != mms.KStructure {
		return mms.Data{}, errors.New("the control structure is not a structure")
	}
	if !o.OperTm.IsZero() && !slices.ContainsFunc(t.Components, func(c mms.Component) bool { return c.Name == "operTm" }) {
		return mms.Data{}, errors.New("the control object does not support time activated operate (no operTm)")
	}
	out := mms.Structure()
	for _, c := range t.Components {
		var d mms.Data
		var err error
		switch c.Name {
		case "ctlVal":
			if d, err = FromJSON(c.Type, value); err != nil {
				return mms.Data{}, fmt.Errorf("ctlVal: %w", err)
			}
		case "operTm":
			d = mms.Timestamp(o.OperTm)
		case "origin":
			cat := o.OrCat
			if cat == 0 {
				cat = 3
			}
			d = mms.Structure(mms.Integer(int64(cat)), mms.Octets([]byte(o.OrIdent)))
		case "ctlNum":
			d = mms.Unsigned(uint64(num))
		case "T":
			d = mms.Timestamp(time.Now())
		case "Test":
			d = mms.Boolean(o.Test)
		case "Check":
			b := mms.NewBitString(max(2, abs(c.Type.Size)))
			b.Set(0, o.SynchroCheck)
			b.Set(1, o.InterlockCheck)
			d = mms.Bits(b)
		default:
			return mms.Data{}, fmt.Errorf("the control structure has an unknown member %s", c.Name)
		}
		out.Elems = append(out.Elems, d)
	}
	return out, nil
}

func (cl *Client) nextCtlNum() uint8 {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.ctlNum++
	return cl.ctlNum
}

// wait registers the waiter of an operation on the control object key.
// One operation runs per object at a time: a select or operate while
// another waits for its answers or termination is refused (its waiter
// would take the first one's events). A cancel is let through, without
// taking the waiter over (cancelling a pending time activated operate).
func (cl *Client) wait(key string, num uint8, cancel bool) (*ctlWaiter, func(), error) {
	w := &ctlWaiter{ch: make(chan ctlEvent, 8), num: int(num)}
	cl.mu.Lock()
	if _, busy := cl.waiters[key]; busy {
		cl.mu.Unlock()
		if cancel {
			return w, func() {}, nil
		}
		return nil, nil, fmt.Errorf("another operation of %s is in progress", key)
	}
	cl.waiters[key] = w
	cl.mu.Unlock()
	return w, func() {
		cl.mu.Lock()
		if cl.waiters[key] == w {
			delete(cl.waiters, key)
		}
		cl.mu.Unlock()
	}, nil
}

// lastCause returns the AddCause and Error of a LastApplError of this
// operation already received (it precedes the write response).
func (w *ctlWaiter) lastCause() (int, int) {
	for {
		select {
		case ev := <-w.ch:
			if !ev.term && ev.addCause >= 0 && w.mine(ev) {
				return ev.addCause, ev.applError
			}
		default:
			return -1, 0
		}
	}
}

// ctlWrite writes Oper, SBOw or Cancel and turns a refusal into a
// ControlError with the LastApplError's AddCause.
func (cl *Client) ctlWrite(ctx context.Context, do Ref, attr, step string, value any, o ControlOptions, w *ctlWaiter, num uint8) error {
	co := do
	co.FC = "CO"
	name := co.Child(attr).MMS()
	t, err := cl.TypeOf(ctx, name)
	if err != nil {
		return &ControlError{Object: do.String(), Step: step, AddCause: -1, Err: err}
	}
	v, err := cl.ctlStruct(t, value, o, num)
	if err != nil {
		return &ControlError{Object: do.String(), Step: step, AddCause: -1, Err: err}
	}
	if err := cl.c.WriteOne(ctx, name, v); err != nil {
		cause, applErr := w.lastCause()
		return &ControlError{Object: do.String(), Step: step, AddCause: cause, ApplError: applErr, Err: err}
	}
	return nil
}

// Operate runs a control on the data object do ("LD/LN.DO") with the
// sequence its control model needs: select first for the SBO models, and
// for enhanced security wait for CommandTermination.
func (cl *Client) Operate(ctx context.Context, do Ref, value any, o ControlOptions) error {
	model, err := cl.ControlModel(ctx, do)
	if err != nil {
		return err
	}
	if o.Termination <= 0 {
		o.Termination = 10 * time.Second
	}
	co := do
	co.FC = "CO"
	key := co.MMS().Domain + "/" + co.MMS().Item
	num := cl.nextCtlNum()
	w, done, err := cl.wait(key, num, false)
	if err != nil {
		return err
	}
	defer done()
	// The service sequence of the control model comes from the model
	// package (IEC 61850-7-2 Clause 20), one source for the rule.
	seq, err := controlSequence(model)
	if err != nil {
		return fmt.Errorf("control model %d of %s is not supported", model, do.String())
	}
	if len(seq) == 0 {
		return &ControlError{Object: do.String(), Step: "operate", AddCause: 1, Err: errors.New("the object is status-only")}
	}
	switch seq[0] {
	case iecmodel.SvcSelect:
		d, err := cl.c.ReadOne(ctx, co.Child("SBO").MMS())
		if err != nil || d.Str == "" {
			if err == nil {
				err = errors.New("the IED returned an empty selection")
			}
			return &ControlError{Object: do.String(), Step: "select", AddCause: 3, Err: err}
		}
	case iecmodel.SvcSelectWithValue:
		if err := cl.ctlWrite(ctx, do, "SBOw", "select", value, o, w, num); err != nil {
			return err
		}
	}
	if err := cl.ctlWrite(ctx, do, "Oper", "operate", value, o, w, num); err != nil {
		return err
	}
	if seq[len(seq)-1] != iecmodel.SvcCommandTermination {
		return nil
	}
	if wait := time.Until(o.OperTm); wait > 0 {
		o.Termination += wait
	}
	timer := time.NewTimer(o.Termination)
	defer timer.Stop()
	for {
		select {
		case ev := <-w.ch:
			if !ev.term || !w.mine(ev) {
				continue
			}
			if ev.addCause >= 0 {
				return &ControlError{Object: do.String(), Step: "termination", AddCause: ev.addCause, ApplError: ev.applError}
			}
			return nil
		case <-timer.C:
			return &ControlError{Object: do.String(), Step: "termination", AddCause: -1,
				Err: fmt.Errorf("no CommandTermination within %s", o.Termination)}
		case <-cl.c.Done():
			return &ControlError{Object: do.String(), Step: "termination", AddCause: -1, Err: cl.c.Err()}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Select selects a control (SBOw for enhanced security, SBO read for
// normal security) without operating it.
func (cl *Client) Select(ctx context.Context, do Ref, value any, o ControlOptions) error {
	model, err := cl.ControlModel(ctx, do)
	if err != nil {
		return err
	}
	co := do
	co.FC = "CO"
	switch model {
	case SBOEnhanced:
		key := co.MMS().Domain + "/" + co.MMS().Item
		num := cl.nextCtlNum()
		w, done, err := cl.wait(key, num, false)
		if err != nil {
			return err
		}
		defer done()
		return cl.ctlWrite(ctx, do, "SBOw", "select", value, o, w, num)
	case SBONormal:
		d, err := cl.c.ReadOne(ctx, co.Child("SBO").MMS())
		if err != nil || d.Str == "" {
			return &ControlError{Object: do.String(), Step: "select", AddCause: 3, Err: err}
		}
		return nil
	}
	return &ControlError{Object: do.String(), Step: "select", AddCause: 1,
		Err: fmt.Errorf("the control model is %s", modelName(model))}
}

// Cancel cancels a selection.
func (cl *Client) Cancel(ctx context.Context, do Ref, value any, o ControlOptions) error {
	co := do
	co.FC = "CO"
	key := co.MMS().Domain + "/" + co.MMS().Item
	num := cl.nextCtlNum()
	w, done, _ := cl.wait(key, num, true)
	defer done()
	return cl.ctlWrite(ctx, do, "Cancel", "cancel", value, o, w, num)
}

// controlSequence gives the services of a ctlModel value (nil for
// status-only).
func controlSequence(ctlModel int) ([]iecmodel.Service, error) {
	return (&iecmodel.ControlInfo{}).Sequence(strconv.Itoa(ctlModel))
}

func modelName(m int) string {
	if m >= 0 && m < len(modelNames) {
		return modelNames[m]
	}
	return fmt.Sprint(m)
}

// DefaultChecks are the Check bits (IEC 61850-7-2 control model, Check
// parameter) a control of the data object ref ("LD/LN.DO", "LN.DO" or the
// MMS form "LN$CO$DO") should carry when its configuration does not say:
// interlock check on for every control, and synchrocheck on for the
// switch position (Pos) of a CSWI or XCBR logical node (with any prefix
// and instance), a breaker or disconnector. An explicit setting overrides
// either.
func DefaultChecks(ref string) (interlock, synchro bool) {
	return true, switchPosition(ref)
}

// switchPosition says whether ref is the Pos of a CSWI or XCBR logical
// node, the position of a breaker or switch.
func switchPosition(ref string) bool {
	if i := strings.IndexByte(ref, '/'); i >= 0 {
		ref = ref[i+1:]
	}
	ln, do, ok := strings.Cut(strings.ReplaceAll(ref, "$", "."), ".")
	if !ok {
		return false
	}
	do, _, _ = strings.Cut(do, ".")
	if do == "CO" { // LN$CO$Pos
		_, rest, _ := strings.Cut(strings.ReplaceAll(ref, "$", "."), ".CO.")
		do, _, _ = strings.Cut(rest, ".")
	}
	if do != "Pos" {
		return false
	}
	ln = strings.TrimRight(ln, "0123456789")
	return strings.HasSuffix(ln, "CSWI") || strings.HasSuffix(ln, "XCBR")
}
