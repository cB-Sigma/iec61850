package iec61850

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

// Logs: the log control block (LCB, FC LG) and the log it writes to, an
// MMS journal (IEC 61850-8-1 17.3). QueryLogByTime and QueryLogAfter map
// to ReadJournal (ISO 9506-2 23.2); a log entry is a journal entry whose
// content lists, per data set member, a variable tagged with its data
// reference and one tagged "ReasonCode" (8-1 17.3.3.4.4).

// LCB is a log control block's state (GetLCBValues, 8-1 17.3.4.2, Table
// 75).
type LCB struct {
	LogEna    bool   `json:"logEna"`
	LogRef    string `json:"logRef"`
	DatSet    string `json:"datSet"`
	TrgOps    []string
	IntgPd    uint64    `json:"intgPd,omitempty"`
	OldEntrTm time.Time `json:"-"`
	NewEntrTm time.Time `json:"-"`
	OldEnt    []byte    `json:"-"`
	NewEnt    []byte    `json:"-"`
}

// ReadLCB reads a log control block (ref "LD/LLN0$LG$name").
func (cl *Client) ReadLCB(ctx context.Context, lcb Ref) (LCB, error) {
	t, err := cl.TypeOf(ctx, lcb.MMS())
	if err != nil {
		return LCB{}, err
	}
	d, err := cl.c.ReadOne(ctx, lcb.MMS())
	if err != nil {
		return LCB{}, fmt.Errorf("reading %s: %w", lcb.String(), err)
	}
	if t.Kind != mms.KStructure || d.Kind != mms.KStructure || len(d.Elems) != len(t.Components) {
		return LCB{}, fmt.Errorf("%s is not a log control block", lcb.String())
	}
	var out LCB
	for i, c := range t.Components {
		v := d.Elems[i]
		switch c.Name {
		case "LogEna":
			out.LogEna = v.Bool
		case "LogRef":
			out.LogRef = v.Str
		case "DatSet":
			out.DatSet = v.Str
		case "IntgPd":
			out.IntgPd = v.Uint
		case "TrgOps":
			for name, b := range triggerBits {
				if v.Bits.Get(b) {
					out.TrgOps = append(out.TrgOps, name)
				}
			}
		// OldEnt and NewEnt are the 8-1 component names (Table 75); the
		// 7-2 attribute names OldEntr and NewEntr are accepted too.
		case "OldEntrTm":
			out.OldEntrTm, _ = mms.DecodeBinaryTime(v.Bytes)
		case "NewEntrTm":
			out.NewEntrTm, _ = mms.DecodeBinaryTime(v.Bytes)
		case "OldEnt", "OldEntr":
			out.OldEnt = v.Bytes
		case "NewEnt", "NewEntr":
			out.NewEnt = v.Bytes
		}
	}
	return out, nil
}

// EnableLog sets a log control block's data set and trigger options when
// given and enables it (SetLCBValues, 8-1 17.3.4.3: LogRef, DatSet,
// TrgOps and IntgPd can only be written while LogEna is false).
func (cl *Client) EnableLog(ctx context.Context, lcb Ref, dataSet string, trgOps []string, intgPd time.Duration) error {
	cur, err := cl.ReadLCB(ctx, lcb)
	if err != nil {
		return err
	}
	w := func(attr string, v mms.Data) error {
		if err := cl.c.WriteOne(ctx, lcb.Child(attr).MMS(), v); err != nil {
			return fmt.Errorf("writing %s of %s: %w", attr, lcb.String(), err)
		}
		return nil
	}
	if dataSet == "" && len(trgOps) == 0 && intgPd == 0 && cur.LogEna {
		return nil
	}
	if cur.LogEna {
		if err := w("LogEna", mms.Boolean(false)); err != nil {
			return err
		}
	}
	if dataSet != "" && dataSet != cur.DatSet {
		if err := w("DatSet", mms.Visible(dataSet)); err != nil {
			return err
		}
	}
	if len(trgOps) > 0 {
		trg := mms.NewBitString(6)
		for _, name := range trgOps {
			b, ok := triggerBits[name]
			if !ok {
				return fmt.Errorf("trigger option %q is not dchg, qchg, dupd, integrity or gi", name)
			}
			trg.Set(b, true)
		}
		if err := w("TrgOps", mms.Bits(trg)); err != nil {
			return err
		}
	}
	if intgPd > 0 {
		if err := w("IntgPd", mms.Unsigned(uint64(intgPd.Milliseconds()))); err != nil {
			return err
		}
	}
	return w("LogEna", mms.Boolean(true))
}

// LogEntry is one entry of a log (8-1 17.3.3.4, Table 77).
type LogEntry struct {
	EntryID []byte
	Time    time.Time // TimeOfLog
	// Values are the logged data (information type DATA).
	Values []LogValue
	// Event is set for an entry that journals a LogEna transition
	// (information type EVENT-DATA): the control block and its state (0
	// disabled, 1 idle, 2 active).
	Event *LogEvent
	// Annotation is the text of an ANNOTATION entry.
	Annotation string
}

// LogValue is a logged data reference with its value and reason code.
type LogValue struct {
	Ref     string // "LD/LN$FC$DO…"
	Value   mms.Data
	Reasons []string
}

// LogEvent is an EVENT-DATA entry.
type LogEvent struct {
	Condition mms.ObjectName
	State     int
}

// logReasonNames are the ReasonForInclusionInLog bits (8-1 8.1.3.11
// Table 39; bit 0 is reserved).
var logReasonNames = []string{"reserved", "dchg", "qchg", "dupd", "integrity", "gi", "application"}

// maxLogPages bounds one query's ReadJournal continuations.
const maxLogPages = 1000

// QueryLogByTime reads the entries of a log between two times
// (QueryLogByTime, 8-1 17.3.4.5: ReadJournal with startingTime and
// endingTime); a zero time leaves that end open. The IED may answer in
// parts (moreFollows); the rest is read after the last entry received.
func (cl *Client) QueryLogByTime(ctx context.Context, log string, from, to time.Time) ([]LogEntry, error) {
	r, err := logByTimeRequest(log, from, to)
	if err != nil {
		return nil, err
	}
	return cl.readLog(ctx, r)
}

// Open ends of a QueryLogByTime: the first and the last instant a
// TimeOfDay with days can carry (days since 1984-01-01 in 16 bits).
var (
	logTimeFirst = time.Date(1984, 1, 1, 0, 0, 0, 0, time.UTC)
	logTimeLast  = logTimeFirst.AddDate(0, 0, 65535).Add(24*time.Hour - time.Millisecond)
)

// logByTimeRequest builds the ReadJournal of QueryLogByTime. Both range
// specifications are always sent, an open end as the first or last
// TimeOfDay: some IEDs (libiec61850 1.6) reject a ReadJournal that has a
// start without a stop as an invalid argument.
func logByTimeRequest(log string, from, to time.Time) (mms.ReadJournalRequest, error) {
	name, err := ParseObjectReference(log)
	if err != nil {
		return mms.ReadJournalRequest{}, err
	}
	if from.IsZero() || from.Before(logTimeFirst) {
		from = logTimeFirst
	}
	if to.IsZero() || to.After(logTimeLast) {
		to = logTimeLast
	}
	return mms.ReadJournalRequest{Journal: name, StartTime: from, HasStart: true, EndTime: to, HasStop: true}, nil
}

// QueryLogAfter reads the entries after the entry with the time and
// EntryID given (QueryLogAfter, 8-1 17.3.4.6: ReadJournal with
// entryToStartAfter); a nil entry reads the whole log.
func (cl *Client) QueryLogAfter(ctx context.Context, log string, at time.Time, entry []byte) ([]LogEntry, error) {
	name, err := ParseObjectReference(log)
	if err != nil {
		return nil, err
	}
	r := mms.ReadJournalRequest{Journal: name, AfterTime: at, AfterEntry: entry, HasAfter: len(entry) > 0}
	return cl.readLog(ctx, r)
}

// readLog runs ReadJournal until the IED has no more, continuing after
// the last entry received.
func (cl *Client) readLog(ctx context.Context, r mms.ReadJournalRequest) ([]LogEntry, error) {
	var out []LogEntry
	for page := 0; page < maxLogPages; page++ {
		entries, more, err := cl.c.ReadJournal(ctx, r)
		if err != nil {
			return out, err
		}
		for _, e := range entries {
			out = append(out, LogEntryFrom(e))
		}
		if !more {
			return out, nil
		}
		if len(entries) == 0 {
			return out, errors.New("the IED said more entries follow but sent none")
		}
		last := entries[len(entries)-1]
		r.HasStart, r.StartEntry = false, nil
		r.AfterTime, r.AfterEntry, r.HasAfter = last.Time, last.EntryID, true
	}
	return out, fmt.Errorf("the log did not end after %d parts", maxLogPages)
}

// LogEntryFrom reads a journal entry as a log entry: each journal
// variable tagged with a data reference is a value, and the "ReasonCode"
// variable after it its reason (8-1 17.3.3.4.4).
func LogEntryFrom(j mms.JournalEntry) LogEntry {
	e := LogEntry{EntryID: j.EntryID, Time: j.Time, Annotation: j.Annotation}
	if j.Event != nil {
		e.Event = &LogEvent{Condition: j.Event.Condition, State: j.Event.State}
	}
	for _, v := range j.Variables {
		if v.Tag == "ReasonCode" {
			if len(e.Values) > 0 && v.Value.Kind == mms.KBitString {
				lv := &e.Values[len(e.Values)-1]
				for b, name := range logReasonNames {
					if b > 0 && v.Value.Bits.Get(b) {
						lv.Reasons = append(lv.Reasons, name)
					}
				}
			}
			continue
		}
		e.Values = append(e.Values, LogValue{Ref: v.Tag, Value: v.Value})
	}
	return e
}

// JournalEntry is a log entry as a journal entry (for servers): each value
// followed by its ReasonCode variable, a 7-bit string (8-1 8.1.3.11).
func (e LogEntry) JournalEntry() mms.JournalEntry {
	j := mms.JournalEntry{EntryID: e.EntryID, Time: e.Time, Annotation: e.Annotation}
	if e.Event != nil {
		j.Event = &mms.JournalEvent{Condition: e.Event.Condition, State: e.Event.State}
	}
	for _, v := range e.Values {
		rc := mms.NewBitString(7)
		for b, name := range logReasonNames {
			if b > 0 && slices.Contains(v.Reasons, name) {
				rc.Set(b, true)
			}
		}
		j.Variables = append(j.Variables, mms.JournalVariable{Tag: v.Ref, Value: v.Value},
			mms.JournalVariable{Tag: "ReasonCode", Value: mms.Bits(rc)})
	}
	return j
}
