package mms

import (
	"errors"
	"time"
)

// The unconfirmed EventNotification service (ISO 9506-2:2003 18.3,
// ISO 9506-1:2003 18.3) and the event types it shares with the event
// management services (eventsvc.go). The layout was first written without
// the standard (findings F-528); it is now checked against it.

// Event condition states (EC-State, ISO 9506-1:2003 19.1.1.4).
const (
	ECStateDisabled = 0
	ECStateIdle     = 1
	ECStateActive   = 2
)

// EventTime is an EventTime CHOICE (ISO 9506-1:2003 19.1.1.12): a time of
// day, a time sequence identifier, or undefined (the zero value).
type EventTime struct {
	Time time.Time
	// Seq is a time sequence identifier, used when IsSeq is set.
	Seq   uint32
	IsSeq bool
}

// Defined reports whether the time is not undefined.
func (t EventTime) Defined() bool { return t.IsSeq || !t.Time.IsZero() }

// Equal compares two event times.
func (t EventTime) Equal(o EventTime) bool {
	if t.IsSeq || o.IsSeq {
		return t.IsSeq == o.IsSeq && t.Seq == o.Seq
	}
	return timeOfDay(t.Time) == timeOfDay(o.Time)
}

// timeOfDay is the 6-octet TimeOfDay of t (millisecond resolution), or ""
// for the zero time.
func timeOfDay(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return string(BinaryTime(t).Bytes)
}

// encode is the CHOICE element: timeOfDay [0], timeSequenceIdentifier [1]
// or undefined [2].
func (t EventTime) encode() []byte {
	switch {
	case t.IsSeq:
		return Uint(0x81, uint64(t.Seq))
	case !t.Time.IsZero():
		return T(0x80, BinaryTime(t.Time).Bytes)
	}
	return T(0x82)
}

// eventTime wraps the CHOICE in the context tag of the field carrying it.
func eventTime(tag byte, t EventTime) []byte { return T(tag, t.encode()) }

// decodeEventTime decodes an explicitly tagged EventTime field.
func decodeEventTime(e Elem) (EventTime, error) {
	in, _, err := Parse(e.Val)
	if err != nil {
		return EventTime{}, err
	}
	switch in.Tag {
	case 0x80:
		t, err := DecodeBinaryTime(in.Val)
		return EventTime{Time: t}, err
	case 0x81:
		v, err := DecodeUint(in.Val)
		return EventTime{Seq: uint32(v), IsSeq: true}, err
	case 0x82:
		return EventTime{}, nil
	}
	return EventTime{}, errors.New("mms: an event time with an unknown alternative")
}

// ActionResult is the result of the event action executed for a
// notification: the action's name and the response to its confirmed
// service request (the ConfirmedServiceResponse element) or the error.
type ActionResult struct {
	Action   ObjectName
	Success  bool
	Response []byte // success: the ConfirmedServiceResponse alternative
	// Failure: the error, and the position of the modifier that failed
	// (nil when the service itself failed).
	Error            ServiceError
	ModifierPosition *uint32
}

// EventNotification is the content of an unconfirmed EventNotification.
type EventNotification struct {
	Enrollment ObjectName
	Condition  ObjectName
	Severity   int // 0 (most severe) to 127
	// State is the condition's state after the transition (ECState…);
	// NoState omits it (a deleted or unavailable condition).
	State   int
	NoState bool
	// Time is the transition time of day; TimeSeq, when set, is a time
	// sequence identifier instead. Both zero is undefined.
	Time             time.Time
	TimeSeq          *uint32
	NotificationLost bool
	// AckRule is the enrollment's alarm acknowledgement rule (AckNone…),
	// included for monitored conditions only (HasAckRule).
	AckRule    int
	HasAckRule bool
	Action     *ActionResult
}

// EventTime is the notification's transition time.
func (n EventNotification) EventTime() EventTime {
	if n.TimeSeq != nil {
		return EventTime{Seq: *n.TimeSeq, IsSeq: true}
	}
	return EventTime{Time: n.Time}
}

// EventNotificationPDU encodes an unconfirmed-PDU carrying the
// notification (UnconfirmedService [2], ISO 9506-2:2003 18.3):
// eventEnrollmentName [0] and eventConditionName [1] (ObjectName, explicit),
// severity [2], currentState [3] OPTIONAL, transitionTime [4] (EventTime,
// explicit), notificationLost [6] DEFAULT FALSE, alarmAcknowledgmentRule
// [7] OPTIONAL and actionResult [8] OPTIONAL.
func EventNotificationPDU(n EventNotification) []byte {
	parts := [][]byte{T(0xa0, n.Enrollment.Encode()), T(0xa1, n.Condition.Encode()), Uint(0x82, uint64(n.Severity))}
	if !n.NoState {
		parts = append(parts, Int(0x83, int64(n.State)))
	}
	parts = append(parts, eventTime(0xa4, n.EventTime()))
	if n.NotificationLost {
		parts = append(parts, Bool(0x86, true))
	}
	if n.HasAckRule {
		parts = append(parts, Int(0x87, int64(n.AckRule)))
	}
	if a := n.Action; a != nil {
		var sf []byte
		if a.Success {
			sf = T(0xa0, a.Response)
		} else {
			var f [][]byte
			if a.ModifierPosition != nil {
				f = append(f, Uint(0x80, uint64(*a.ModifierPosition)))
			}
			f = append(f, T(0xa1, a.Error.contents()...))
			sf = T(0xa1, f...)
		}
		parts = append(parts, T(0xa8, a.Action.Encode(), sf))
	}
	return T(TagUnconfirmed, T(0xa0|UsvcEventNotification, parts...))
}

// DecodeEventNotification decodes an unconfirmed-PDU carrying an
// EventNotification.
func DecodeEventNotification(e Elem) (EventNotification, error) {
	kids, err := e.Children()
	if err != nil || len(kids) == 0 || kids[0].Tag != 0xa0|UsvcEventNotification {
		return EventNotification{}, errors.New("mms: not an event notification")
	}
	parts, err := kids[0].Children()
	if err != nil {
		return EventNotification{}, err
	}
	n := EventNotification{NoState: true}
	seen := 0
	for _, p := range parts {
		switch p.Tag {
		case 0xa0, 0xa1:
			in, _, err := Parse(p.Val)
			if err != nil {
				return EventNotification{}, err
			}
			name, err := DecodeObjectName(in)
			if err != nil {
				return EventNotification{}, err
			}
			if p.Tag == 0xa0 {
				n.Enrollment = name
			} else {
				n.Condition = name
			}
			seen |= 1 << (p.Tag & 1)
		case 0x82:
			v, _ := DecodeUint(p.Val)
			n.Severity = int(v)
			seen |= 4
		case 0x83:
			v, _ := DecodeUint(p.Val)
			n.State, n.NoState = int(v), false
		case 0xa4:
			t, err := decodeEventTime(p)
			if err != nil {
				return EventNotification{}, err
			}
			if t.IsSeq {
				n.TimeSeq = &t.Seq
			} else {
				n.Time = t.Time
			}
			seen |= 8
		case 0x86:
			n.NotificationLost = len(p.Val) == 1 && p.Val[0] != 0
		case 0x87:
			v, _ := DecodeInt(p.Val)
			n.AckRule, n.HasAckRule = int(v), true
		case 0xa8:
			a, err := decodeActionResult(p)
			if err != nil {
				return EventNotification{}, err
			}
			n.Action = a
		}
	}
	if seen != 15 {
		return EventNotification{}, errors.New("mms: an event notification without its names, severity or transition time")
	}
	return n, nil
}

func decodeActionResult(p Elem) (*ActionResult, error) {
	kids, err := p.Children()
	if err != nil || len(kids) != 2 {
		return nil, errors.New("mms: a bad action result")
	}
	name, err := DecodeObjectName(kids[0])
	if err != nil {
		return nil, err
	}
	a := &ActionResult{Action: name}
	switch kids[1].Tag {
	case 0xa0:
		a.Success = true
		a.Response = append([]byte(nil), kids[1].Val...)
	case 0xa1:
		f, err := kids[1].Children()
		if err != nil {
			return nil, err
		}
		for _, x := range f {
			switch x.Tag {
			case 0x80:
				v, _ := DecodeUint(x.Val)
				pos := uint32(v)
				a.ModifierPosition = &pos
			case 0xa1:
				if a.Error, err = DecodeServiceError(x.Val); err != nil {
					return nil, err
				}
			}
		}
	default:
		return nil, errors.New("mms: an action result that is neither success nor failure")
	}
	return a, nil
}

// SendEventNotification sends an EventNotification on a server
// association.
func (s *ServerConn) SendEventNotification(n EventNotification) error {
	return s.Send(EventNotificationPDU(n))
}
