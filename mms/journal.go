package mms

import (
	"context"
	"errors"
	"time"
)

// ReadJournal (ISO 9506-2:2003 23.2, 23.8.1): the journal services IEC
// 61850-8-1 17.3.4 maps QueryLogByTime and QueryLogAfter onto. Times are
// TimeOfDay values of six octets.

// ReadJournalRequest is a ReadJournal-Request: the journal and at most one
// start (a time or an entry), one stop (a time or a number of entries)
// and the entry to start after.
type ReadJournalRequest struct {
	Journal ObjectName
	// rangeStartSpecification: StartTime [0] or StartEntry [1].
	StartTime  time.Time
	StartEntry []byte
	HasStart   bool
	// rangeStopSpecification: EndTime [0] or Count [1] (numberOfEntries).
	EndTime time.Time
	Count   int
	HasStop bool
	// Variables is listOfVariables: only entries with these journal
	// variable tags (empty for all).
	Variables []string
	// entryToStartAfter: the time and identifier of an entry.
	AfterTime  time.Time
	AfterEntry []byte
	HasAfter   bool
}

// JournalEntry is a JournalEntry: its identifier and content.
type JournalEntry struct {
	EntryID []byte
	Time    time.Time // occurrenceTime
	// Event is the data form's event (an event condition and its state:
	// 0 disabled, 1 idle, 2 active).
	Event *JournalEvent
	// Variables are the data form's journal variables.
	Variables []JournalVariable
	// Annotation is the annotation form's text.
	Annotation string
}

// JournalEvent is the event of a journal entry's data.
type JournalEvent struct {
	Condition ObjectName
	State     int
}

// JournalVariable is a Journal-Variable: a tag and a value.
type JournalVariable struct {
	Tag   string
	Value Data
}

// TimeOfDay6 is the six-octet TimeOfDay of t.
func TimeOfDay6(t time.Time) []byte { return BinaryTime(t).Bytes }

// Encode is the readJournal choice of a ConfirmedServiceRequest.
func (r ReadJournalRequest) Encode() []byte {
	parts := [][]byte{T(0xa0, r.Journal.Encode())}
	if r.HasStart {
		if r.StartEntry != nil {
			parts = append(parts, T(0xa1, T(0x81, r.StartEntry)))
		} else {
			parts = append(parts, T(0xa1, T(0x80, TimeOfDay6(r.StartTime))))
		}
	}
	if r.HasStop {
		if r.Count > 0 {
			parts = append(parts, T(0xa2, Int(0x81, int64(r.Count))))
		} else {
			parts = append(parts, T(0xa2, T(0x80, TimeOfDay6(r.EndTime))))
		}
	}
	if len(r.Variables) > 0 {
		vars := make([][]byte, len(r.Variables))
		for i, v := range r.Variables {
			vars[i] = Str(0x1a, v)
		}
		parts = append(parts, T(0xa4, vars...))
	}
	if r.HasAfter {
		parts = append(parts, T(0xa5, T(0x80, TimeOfDay6(r.AfterTime)), T(0x81, r.AfterEntry)))
	}
	return svc(SvcReadJournal, parts...)
}

// DecodeReadJournal decodes a ReadJournal-Request.
func DecodeReadJournal(body Elem) (ReadJournalRequest, error) {
	var r ReadJournalRequest
	kids, err := body.Children()
	if err != nil {
		return r, err
	}
	named := false
	for _, k := range kids {
		switch {
		case k.Context(0):
			in, _, err := Parse(k.Val)
			if err != nil {
				return r, err
			}
			if r.Journal, err = DecodeObjectName(in); err != nil {
				return r, err
			}
			named = true
		case k.Context(1), k.Context(2):
			in, _, err := Parse(k.Val)
			if err != nil {
				return r, err
			}
			switch {
			case k.Context(1) && in.Context(0):
				r.StartTime, err = DecodeBinaryTime(in.Val)
			case k.Context(1) && in.Context(1):
				r.StartEntry = in.Val
			case k.Context(2) && in.Context(0):
				r.EndTime, err = DecodeBinaryTime(in.Val)
			case k.Context(2) && in.Context(1):
				var n int64
				n, err = DecodeInt(in.Val)
				if err == nil && n < 1 {
					err = errors.New("mms: numberOfEntries below 1")
				}
				r.Count = int(n)
			default:
				err = errors.New("mms: a bad journal range")
			}
			if err != nil {
				return r, err
			}
			if k.Context(1) {
				r.HasStart = true
			} else {
				r.HasStop = true
			}
		case k.Context(4):
			vars, err := k.Children()
			if err != nil {
				return r, err
			}
			for _, v := range vars {
				r.Variables = append(r.Variables, string(v.Val))
			}
		case k.Context(5):
			in, err := k.Children()
			if err != nil || len(in) != 2 || !in[0].Context(0) || !in[1].Context(1) {
				return r, errors.New("mms: a bad entryToStartAfter")
			}
			if r.AfterTime, err = DecodeBinaryTime(in[0].Val); err != nil {
				return r, err
			}
			r.AfterEntry, r.HasAfter = in[1].Val, true
		}
	}
	if !named {
		return r, errors.New("mms: a ReadJournal request without a journal name")
	}
	return r, nil
}

// ReadJournalResponse is the readJournal choice of a
// ConfirmedServiceResponse with the entries and moreFollows.
func ReadJournalResponse(entries []JournalEntry, more bool) []byte {
	items := make([][]byte, len(entries))
	for i, e := range entries {
		var form []byte
		if e.Event == nil && e.Variables == nil && e.Annotation != "" {
			form = Str(0x83, e.Annotation)
		} else {
			var data [][]byte
			if e.Event != nil {
				data = append(data, T(0xa0, T(0xa0, e.Event.Condition.Encode()), Int(0x81, int64(e.Event.State))))
			}
			if len(e.Variables) > 0 {
				vars := make([][]byte, len(e.Variables))
				for j, v := range e.Variables {
					vars[j] = T(0x30, Str(0x80, v.Tag), T(0xa1, v.Value.Encode()))
				}
				data = append(data, T(0xa1, vars...))
			}
			form = T(0xa2, data...)
		}
		// originatingApplication is an empty ApplicationReference.
		items[i] = T(0x30, T(0x80, e.EntryID), T(0xa1, T(0x30)), T(0xa2, T(0x80, TimeOfDay6(e.Time)), form))
	}
	parts := [][]byte{T(0xa0, items...)}
	if more {
		parts = append(parts, Bool(0x81, true))
	}
	return svc(SvcReadJournal, parts...)
}

// DecodeReadJournalResponse decodes a ReadJournal-Response.
func DecodeReadJournalResponse(body Elem) ([]JournalEntry, bool, error) {
	kids, err := body.Children()
	if err != nil {
		return nil, false, err
	}
	var out []JournalEntry
	more := false
	for _, k := range kids {
		switch {
		case k.Context(0):
			list, err := k.Children()
			if err != nil {
				return nil, false, err
			}
			for _, je := range list {
				e, err := decodeJournalEntry(je)
				if err != nil {
					return nil, false, err
				}
				out = append(out, e)
			}
		case k.Context(1):
			more = len(k.Val) == 1 && k.Val[0] != 0
		}
	}
	return out, more, nil
}

func decodeJournalEntry(je Elem) (JournalEntry, error) {
	var e JournalEntry
	parts, err := je.Children()
	if err != nil {
		return e, err
	}
	for _, p := range parts {
		switch {
		case p.Context(0):
			e.EntryID = p.Val
		case p.Context(2):
			content, err := p.Children()
			if err != nil {
				return e, err
			}
			for _, c := range content {
				switch {
				case c.Context(0):
					if e.Time, err = DecodeBinaryTime(c.Val); err != nil {
						return e, err
					}
				case c.Context(3):
					e.Annotation = string(c.Val)
				case c.Context(2):
					if err := decodeEntryData(c, &e); err != nil {
						return e, err
					}
				}
			}
		}
	}
	if e.EntryID == nil {
		return e, errors.New("mms: a journal entry without an entry identifier")
	}
	return e, nil
}

func decodeEntryData(c Elem, e *JournalEntry) error {
	kids, err := c.Children()
	if err != nil {
		return err
	}
	for _, k := range kids {
		switch {
		case k.Context(0):
			ev, err := k.Children()
			if err != nil {
				return err
			}
			e.Event = &JournalEvent{}
			for _, x := range ev {
				switch {
				case x.Context(0):
					in, _, err := Parse(x.Val)
					if err != nil {
						return err
					}
					if e.Event.Condition, err = DecodeObjectName(in); err != nil {
						return err
					}
				case x.Context(1):
					n, err := DecodeInt(x.Val)
					if err != nil {
						return err
					}
					e.Event.State = int(n)
				}
			}
		case k.Context(1):
			vars, err := k.Children()
			if err != nil {
				return err
			}
			for _, v := range vars {
				f, err := v.Children()
				if err != nil || len(f) != 2 || !f[0].Context(0) || !f[1].Context(1) {
					return errors.New("mms: a journal variable is not a tag and a value")
				}
				in, _, err := Parse(f[1].Val)
				if err != nil {
					return err
				}
				d, err := DecodeData(in)
				if err != nil {
					return err
				}
				e.Variables = append(e.Variables, JournalVariable{Tag: string(f[0].Val), Value: d})
			}
		}
	}
	return nil
}

// ReadJournal reads journal entries: one response, whose moreFollows
// says whether the client should ask again after the last entry.
func (c *Client) ReadJournal(ctx context.Context, r ReadJournalRequest) ([]JournalEntry, bool, error) {
	body, err := c.call(ctx, r.Encode(), SvcReadJournal)
	if err != nil {
		return nil, false, err
	}
	return DecodeReadJournalResponse(body)
}
