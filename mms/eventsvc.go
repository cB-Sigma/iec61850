package mms

import (
	"context"
	"errors"
	"fmt"
)

// The event management services (ISO 9506-2:2003 clauses 18 to 21; the
// object models of ISO 9506-1:2003 clauses 18 to 21): request and
// response encoders and decoders for both sides, and the client calls.
// Every tag comes from the ASN.1 of those clauses; requests whose type is
// an ObjectName or a CHOICE are explicitly tagged (48, 49, 50, 54, 55,
// 56, 58, 60), the others implicitly.

// Event condition classes (EC-Class) and enrollment classes, durations,
// alarm acknowledgement rules and states (ISO 9506-1:2003 19.1.1.3,
// 21.1.1.3, 21.1.1.11, 21.1.1.13, ISO 9506-2:2003 21.7.1).
const (
	ECNetworkTriggered = 0
	ECMonitored        = 1

	EEModifier     = 0
	EENotification = 1

	EECurrent   = 0
	EEPermanent = 1

	AckNone   = 0
	AckSimple = 1
	AckActive = 2
	AckAll    = 3

	EEDisabled     = 0
	EEIdle         = 1
	EEActive       = 2
	EEActiveNoAckA = 3
	EEIdleNoAckI   = 4
	EEIdleNoAckA   = 5
	EEIdleAcked    = 6
	EEActiveAcked  = 7
	EEUndefined    = 8
)

// Transitions bits (ISO 9506-1:2003 21.1.1.5, SIZE(7)).
const (
	TransIdleToDisabled   = 0
	TransActiveToDisabled = 1
	TransDisabledToIdle   = 2
	TransActiveToIdle     = 3
	TransDisabledToActive = 4
	TransIdleToActive     = 5
	TransAnyToDeleted     = 6
	numTransitions        = 7
)

// Transitions builds a Transitions bit string.
func Transitions(set ...int) BitString { return bits(numTransitions, set) }

// NormalPriority and NormalSeverity are the defaults of priority and
// severity (ISO 9506-1:2003 16.1.3.7, 19.1.1.6).
const (
	NormalPriority = 64
	NormalSeverity = 64
)

// Acknowledgement filters of the alarm summaries.
const (
	AckFilterNotAcked = 0
	AckFilterAcked    = 1
	AckFilterAll      = 2
)

// Unacknowledged states of an alarm summary.
const (
	UnackedNone   = 0
	UnackedActive = 1
	UnackedIdle   = 2
	UnackedBoth   = 3
)

// ---- helpers --------------------------------------------------------------

// fields maps a constructed element's context-tagged children by number.
func fields(e Elem) (map[int]Elem, error) {
	kids, err := e.Children()
	if err != nil {
		return nil, err
	}
	m := make(map[int]Elem, len(kids))
	for _, k := range kids {
		if k.Tag&0xc0 == 0x80 {
			m[k.Num] = k
		}
	}
	return m, nil
}

// explicitName decodes an explicitly tagged ObjectName field.
func explicitName(e Elem) (ObjectName, error) {
	in, _, err := Parse(e.Val)
	if err != nil {
		return ObjectName{}, err
	}
	return DecodeObjectName(in)
}

// bodyName decodes a service whose request is an explicitly tagged
// ObjectName (the service element's contents are the name).
func bodyName(body Elem) (ObjectName, error) { return explicitName(body) }

func boolOf(e Elem) bool { return len(e.Val) == 1 && e.Val[0] != 0 }

func intOf(e Elem) int {
	v, _ := DecodeInt(e.Val)
	return int(v)
}

func uintOf(e Elem) uint32 {
	v, _ := DecodeUint(e.Val)
	return uint32(v)
}

func svc(num int, parts ...[]byte) []byte { return TH(0xa0, num, parts...) }

// nullResponse is a response whose type is NULL ([n] IMPLICIT NULL).
func nullResponse(num int) []byte { return TH(0x80, num) }

func unsignedResponse(num int, v uint32) []byte { return TH(0x80, num, UintBytes(uint64(v))) }

func names(tag byte, ns []ObjectName) []byte {
	items := make([][]byte, len(ns))
	for i, n := range ns {
		items[i] = n.Encode()
	}
	return T(tag, items...)
}

func decodeNames(e Elem) ([]ObjectName, error) {
	kids, err := e.Children()
	if err != nil {
		return nil, err
	}
	out := make([]ObjectName, 0, len(kids))
	for _, k := range kids {
		n, err := DecodeObjectName(k)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

// ---- event conditions (clause 19) ------------------------------------------

// EventConditionDef is a DefineEventCondition request.
type EventConditionDef struct {
	Name     ObjectName
	Class    int // ECNetworkTriggered or ECMonitored
	Priority int // 0 highest to 127; NormalPriority by default
	Severity int // 0 most severe to 127; NormalSeverity by default
	// AlarmSummaryReports, Monitored (the boolean variable monitored) and
	// EvaluationInterval (ms) apply to monitored conditions.
	AlarmSummaryReports *bool
	Monitored           *ObjectName
	EvaluationInterval  *uint32
}

// DefineEventConditionRequest is the [47] request.
func DefineEventConditionRequest(d EventConditionDef) []byte {
	parts := [][]byte{T(0xa0, d.Name.Encode()), Int(0x81, int64(d.Class))}
	if d.Priority != NormalPriority {
		parts = append(parts, Uint(0x82, uint64(d.Priority)))
	}
	if d.Severity != NormalSeverity {
		parts = append(parts, Uint(0x83, uint64(d.Severity)))
	}
	if d.AlarmSummaryReports != nil {
		parts = append(parts, Bool(0x84, *d.AlarmSummaryReports))
	}
	if d.Monitored != nil {
		parts = append(parts, T(0xa6, T(0xa0, d.Monitored.Encode())))
	}
	if d.EvaluationInterval != nil {
		parts = append(parts, Uint(0x87, uint64(*d.EvaluationInterval)))
	}
	return svc(SvcDefineEventCondition, parts...)
}

// DecodeDefineEventCondition decodes a [47] request.
func DecodeDefineEventCondition(body Elem) (EventConditionDef, error) {
	f, err := fields(body)
	if err != nil {
		return EventConditionDef{}, err
	}
	d := EventConditionDef{Priority: NormalPriority, Severity: NormalSeverity}
	nm, ok := f[0]
	cl, ok2 := f[1]
	if !ok || !ok2 {
		return d, errors.New("mms: a define event condition request without its name or class")
	}
	if d.Name, err = explicitName(nm); err != nil {
		return d, err
	}
	d.Class = intOf(cl)
	if e, ok := f[2]; ok {
		d.Priority = intOf(e)
	}
	if e, ok := f[3]; ok {
		d.Severity = intOf(e)
	}
	if e, ok := f[4]; ok {
		v := boolOf(e)
		d.AlarmSummaryReports = &v
	}
	if e, ok := f[6]; ok {
		in, _, err := Parse(e.Val)
		if err != nil {
			return d, err
		}
		if in.Tag != 0xa0 {
			return d, errors.New("mms: a monitored variable that is not named")
		}
		n, err := explicitName(in)
		if err != nil {
			return d, err
		}
		d.Monitored = &n
	}
	if e, ok := f[7]; ok {
		v := uintOf(e)
		d.EvaluationInterval = &v
	}
	return d, nil
}

// DeleteScope is the scope of a DeleteEventCondition or DeleteEventAction
// request: specific names, the AA-specific objects of the association, the
// objects of a domain, or the VMD-specific objects.
type DeleteScope struct {
	Specific []ObjectName
	AA       bool
	Domain   string
	VMD      bool
}

// deleteScope encodes the CHOICE with the tags of the service: conditions
// use domain [2] and vmd [3], actions domain [3] and vmd [4] (ISO
// 9506-2:2003 19.3, 20.3).
func (s DeleteScope) encode(domainTag, vmdTag byte) []byte {
	switch {
	case s.AA:
		return T(0x81)
	case s.Domain != "":
		return Str(0x80|domainTag, s.Domain)
	case s.VMD:
		return T(0x80 | vmdTag)
	}
	return names(0xa0, s.Specific)
}

func decodeDeleteScope(body Elem, domainTag, vmdTag int) (DeleteScope, error) {
	in, _, err := Parse(body.Val)
	if err != nil {
		return DeleteScope{}, err
	}
	switch {
	case in.Tag == 0xa0:
		ns, err := decodeNames(in)
		return DeleteScope{Specific: ns}, err
	case in.Tag == 0x81:
		return DeleteScope{AA: true}, nil
	case in.Tag == 0x80|byte(domainTag):
		return DeleteScope{Domain: string(in.Val)}, nil
	case in.Tag == 0x80|byte(vmdTag):
		return DeleteScope{VMD: true}, nil
	}
	return DeleteScope{}, fmt.Errorf("mms: a delete scope with tag %#x", in.Tag)
}

// DeleteEventConditionRequest is the [48] request.
func DeleteEventConditionRequest(s DeleteScope) []byte {
	return svc(SvcDeleteEventCondition, s.encode(2, 3))
}

// DecodeDeleteEventCondition decodes a [48] request.
func DecodeDeleteEventCondition(body Elem) (DeleteScope, error) { return decodeDeleteScope(body, 2, 3) }

// GetEventConditionAttributesRequest is the [49] request.
func GetEventConditionAttributesRequest(n ObjectName) []byte {
	return svc(SvcGetEventConditionAttributes, n.Encode())
}

// EventConditionAttrs is a GetEventConditionAttributes response.
type EventConditionAttrs struct {
	Deletable           bool
	Class               int
	Priority, Severity  int
	AlarmSummaryReports bool
	// Monitored is the monitored variable of a monitored condition; nil
	// with MonitoredUndefined for a monitored condition whose variable is
	// undefined.
	Monitored          *ObjectName
	MonitoredUndefined bool
	EvaluationInterval *uint32
}

// EventConditionAttributesResponse answers [49].
func EventConditionAttributesResponse(a EventConditionAttrs) []byte {
	var parts [][]byte
	if a.Deletable {
		parts = append(parts, Bool(0x80, true))
	}
	parts = append(parts, Int(0x81, int64(a.Class)))
	if a.Priority != NormalPriority {
		parts = append(parts, Uint(0x82, uint64(a.Priority)))
	}
	if a.Severity != NormalSeverity {
		parts = append(parts, Uint(0x83, uint64(a.Severity)))
	}
	if a.AlarmSummaryReports {
		parts = append(parts, Bool(0x84, true))
	}
	switch {
	case a.Monitored != nil:
		parts = append(parts, T(0xa6, T(0xa0, T(0xa0, a.Monitored.Encode()))))
	case a.MonitoredUndefined:
		parts = append(parts, T(0xa6, T(0x81)))
	}
	if a.EvaluationInterval != nil {
		parts = append(parts, Uint(0x87, uint64(*a.EvaluationInterval)))
	}
	return svc(SvcGetEventConditionAttributes, parts...)
}

func decodeEventConditionAttrs(body Elem) (EventConditionAttrs, error) {
	f, err := fields(body)
	if err != nil {
		return EventConditionAttrs{}, err
	}
	a := EventConditionAttrs{Priority: NormalPriority, Severity: NormalSeverity}
	if e, ok := f[0]; ok {
		a.Deletable = boolOf(e)
	}
	e, ok := f[1]
	if !ok {
		return a, errors.New("mms: event condition attributes without the class")
	}
	a.Class = intOf(e)
	if e, ok := f[2]; ok {
		a.Priority = intOf(e)
	}
	if e, ok := f[3]; ok {
		a.Severity = intOf(e)
	}
	if e, ok := f[4]; ok {
		a.AlarmSummaryReports = boolOf(e)
	}
	if e, ok := f[6]; ok {
		in, _, err := Parse(e.Val)
		if err != nil {
			return a, err
		}
		switch in.Tag {
		case 0x81:
			a.MonitoredUndefined = true
		case 0xa0:
			vs, _, err := Parse(in.Val)
			if err != nil {
				return a, err
			}
			if vs.Tag != 0xa0 {
				return a, errors.New("mms: a monitored variable that is not named")
			}
			n, err := explicitName(vs)
			if err != nil {
				return a, err
			}
			a.Monitored = &n
		}
	}
	if e, ok := f[7]; ok {
		v := uintOf(e)
		a.EvaluationInterval = &v
	}
	return a, nil
}

// ReportEventConditionStatusRequest is the [50] request.
func ReportEventConditionStatusRequest(n ObjectName) []byte {
	return svc(SvcReportEventConditionStatus, n.Encode())
}

// EventConditionStatus is a ReportEventConditionStatus response.
type EventConditionStatus struct {
	State          int
	NumEnrollments uint32
	Enabled        *bool
	TimeToActive   EventTime
	TimeToIdle     EventTime
}

// EventConditionStatusResponse answers [50].
func EventConditionStatusResponse(s EventConditionStatus) []byte {
	parts := [][]byte{Int(0x80, int64(s.State)), Uint(0x81, uint64(s.NumEnrollments))}
	if s.Enabled != nil {
		parts = append(parts, Bool(0x82, *s.Enabled))
	}
	if s.TimeToActive.Defined() {
		parts = append(parts, eventTime(0xa3, s.TimeToActive))
	}
	if s.TimeToIdle.Defined() {
		parts = append(parts, eventTime(0xa4, s.TimeToIdle))
	}
	return svc(SvcReportEventConditionStatus, parts...)
}

func decodeEventConditionStatus(body Elem) (EventConditionStatus, error) {
	f, err := fields(body)
	if err != nil {
		return EventConditionStatus{}, err
	}
	var s EventConditionStatus
	st, ok := f[0]
	num, ok2 := f[1]
	if !ok || !ok2 {
		return s, errors.New("mms: an event condition status without its state or enrollment count")
	}
	s.State, s.NumEnrollments = intOf(st), uintOf(num)
	if e, ok := f[2]; ok {
		v := boolOf(e)
		s.Enabled = &v
	}
	if e, ok := f[3]; ok {
		if s.TimeToActive, err = decodeEventTime(e); err != nil {
			return s, err
		}
	}
	if e, ok := f[4]; ok {
		if s.TimeToIdle, err = decodeEventTime(e); err != nil {
			return s, err
		}
	}
	return s, nil
}

// ConditionMonitoring is an AlterEventConditionMonitoring request; at
// least one of the changes is set.
type ConditionMonitoring struct {
	Name                ObjectName
	Enabled             *bool
	Priority            *int
	AlarmSummaryReports *bool
	EvaluationInterval  *uint32 // the cei parameter CBB
}

// AlterEventConditionMonitoringRequest is the [51] request.
func AlterEventConditionMonitoringRequest(m ConditionMonitoring) []byte {
	parts := [][]byte{T(0xa0, m.Name.Encode())}
	if m.Enabled != nil {
		parts = append(parts, Bool(0x81, *m.Enabled))
	}
	if m.Priority != nil {
		parts = append(parts, Uint(0x82, uint64(*m.Priority)))
	}
	if m.AlarmSummaryReports != nil {
		parts = append(parts, Bool(0x83, *m.AlarmSummaryReports))
	}
	if m.EvaluationInterval != nil {
		parts = append(parts, Uint(0x84, uint64(*m.EvaluationInterval)))
	}
	return svc(SvcAlterEventConditionMonitoring, parts...)
}

// DecodeAlterEventConditionMonitoring decodes a [51] request.
func DecodeAlterEventConditionMonitoring(body Elem) (ConditionMonitoring, error) {
	f, err := fields(body)
	if err != nil {
		return ConditionMonitoring{}, err
	}
	var m ConditionMonitoring
	nm, ok := f[0]
	if !ok {
		return m, errors.New("mms: an alter event condition monitoring request without the name")
	}
	if m.Name, err = explicitName(nm); err != nil {
		return m, err
	}
	if e, ok := f[1]; ok {
		v := boolOf(e)
		m.Enabled = &v
	}
	if e, ok := f[2]; ok {
		v := intOf(e)
		m.Priority = &v
	}
	if e, ok := f[3]; ok {
		v := boolOf(e)
		m.AlarmSummaryReports = &v
	}
	if e, ok := f[4]; ok {
		v := uintOf(e)
		m.EvaluationInterval = &v
	}
	if m.Enabled == nil && m.Priority == nil && m.AlarmSummaryReports == nil && m.EvaluationInterval == nil {
		return m, errors.New("mms: an alter event condition monitoring request that changes nothing")
	}
	return m, nil
}

// TriggerEventRequest is the [52] request (priority nil for none).
func TriggerEventRequest(n ObjectName, priority *int) []byte {
	parts := [][]byte{T(0xa0, n.Encode())}
	if priority != nil {
		parts = append(parts, Uint(0x81, uint64(*priority)))
	}
	return svc(SvcTriggerEvent, parts...)
}

// DecodeTriggerEvent decodes a [52] request.
func DecodeTriggerEvent(body Elem) (ObjectName, *int, error) {
	f, err := fields(body)
	if err != nil {
		return ObjectName{}, nil, err
	}
	nm, ok := f[0]
	if !ok {
		return ObjectName{}, nil, errors.New("mms: a trigger event request without the name")
	}
	n, err := explicitName(nm)
	if err != nil {
		return n, nil, err
	}
	if e, ok := f[1]; ok {
		v := intOf(e)
		return n, &v, nil
	}
	return n, nil, nil
}

// ---- event actions (clause 20) ----------------------------------------------

// EventActionDef is a DefineEventAction request: the action's name and the
// confirmed service request to execute (a ConfirmedServiceRequest element,
// as built by the request encoders). Modifiers are not supported.
type EventActionDef struct {
	Name    ObjectName
	Service []byte
}

// DefineEventActionRequest is the [53] request.
func DefineEventActionRequest(d EventActionDef) []byte {
	return svc(SvcDefineEventAction, T(0xa0, d.Name.Encode()), T(0xa2, d.Service))
}

// DecodeDefineEventAction decodes a [53] request; a request with a list of
// modifiers is refused (hasModifiers).
func DecodeDefineEventAction(body Elem) (d EventActionDef, hasModifiers bool, err error) {
	f, err := fields(body)
	if err != nil {
		return d, false, err
	}
	nm, ok := f[0]
	sv, ok2 := f[2]
	if !ok || !ok2 {
		return d, false, errors.New("mms: a define event action request without its name or service")
	}
	if d.Name, err = explicitName(nm); err != nil {
		return d, false, err
	}
	in, _, err := Parse(sv.Val)
	if err != nil || in.Tag&0xc0 != 0x80 {
		return d, false, errors.New("mms: a define event action request whose service is not a confirmed service request")
	}
	d.Service = append([]byte(nil), sv.Val...)
	if m, ok := f[1]; ok && len(m.Val) > 0 {
		hasModifiers = true
	}
	return d, hasModifiers, nil
}

// DeleteEventActionRequest is the [54] request.
func DeleteEventActionRequest(s DeleteScope) []byte { return svc(SvcDeleteEventAction, s.encode(3, 4)) }

// DecodeDeleteEventAction decodes a [54] request.
func DecodeDeleteEventAction(body Elem) (DeleteScope, error) { return decodeDeleteScope(body, 3, 4) }

// GetEventActionAttributesRequest is the [55] request.
func GetEventActionAttributesRequest(n ObjectName) []byte {
	return svc(SvcGetEventActionAttributes, n.Encode())
}

// EventActionAttrs is a GetEventActionAttributes response.
type EventActionAttrs struct {
	Deletable bool
	Service   []byte
}

// EventActionAttributesResponse answers [55] (an empty list of modifiers).
func EventActionAttributesResponse(a EventActionAttrs) []byte {
	var parts [][]byte
	if a.Deletable {
		parts = append(parts, Bool(0x80, true))
	}
	parts = append(parts, T(0xa1), T(0xa2, a.Service))
	return svc(SvcGetEventActionAttributes, parts...)
}

func decodeEventActionAttrs(body Elem) (EventActionAttrs, error) {
	f, err := fields(body)
	if err != nil {
		return EventActionAttrs{}, err
	}
	var a EventActionAttrs
	if e, ok := f[0]; ok {
		a.Deletable = boolOf(e)
	}
	e, ok := f[2]
	if !ok {
		return a, errors.New("mms: event action attributes without the service")
	}
	a.Service = append([]byte(nil), e.Val...)
	return a, nil
}

// ReportEventActionStatusRequest is the [56] request.
func ReportEventActionStatusRequest(n ObjectName) []byte {
	return svc(SvcReportEventActionStatus, n.Encode())
}

// ---- event enrollments (clause 21) -----------------------------------------

// EventEnrollmentDef is a DefineEventEnrollment request (the client is
// the requesting association; third-party enrollment, the tpy CBB, is not
// offered).
type EventEnrollmentDef struct {
	Name        ObjectName
	Condition   ObjectName
	Transitions BitString
	AckRule     int
	Action      *ObjectName
}

// DefineEventEnrollmentRequest is the [57] request.
func DefineEventEnrollmentRequest(d EventEnrollmentDef) []byte {
	parts := [][]byte{T(0xa0, d.Name.Encode()), T(0xa1, d.Condition.Encode()),
		T(0x82, fixed(d.Transitions, numTransitions).Contents()), Int(0x83, int64(d.AckRule))}
	if d.Action != nil {
		parts = append(parts, T(0xa4, d.Action.Encode()))
	}
	return svc(SvcDefineEventEnrollment, parts...)
}

// DecodeDefineEventEnrollment decodes a [57] request; thirdParty reports a
// clientApplication [5].
func DecodeDefineEventEnrollment(body Elem) (d EventEnrollmentDef, thirdParty bool, err error) {
	f, err := fields(body)
	if err != nil {
		return d, false, err
	}
	nm, ok0 := f[0]
	ec, ok1 := f[1]
	tr, ok2 := f[2]
	ar, ok3 := f[3]
	if !ok0 || !ok1 || !ok2 || !ok3 {
		return d, false, errors.New("mms: a define event enrollment request without a mandatory field")
	}
	if d.Name, err = explicitName(nm); err != nil {
		return d, false, err
	}
	if d.Condition, err = explicitName(ec); err != nil {
		return d, false, err
	}
	if d.Transitions, err = DecodeBitString(tr.Val); err != nil {
		return d, false, err
	}
	d.Transitions = fixed(d.Transitions, numTransitions)
	d.AckRule = intOf(ar)
	if e, ok := f[4]; ok {
		n, err := explicitName(e)
		if err != nil {
			return d, false, err
		}
		d.Action = &n
	}
	_, thirdParty = f[5]
	return d, thirdParty, nil
}

// DefineEventEnrollmentError is the ServiceError of a DefineEventEnrollment
// that names an undefined object: the serviceSpecificInfo [8] carries its
// name (ISO 9506-2:2003 21.2.3).
func DefineEventEnrollmentError(undefined ObjectName) ServiceError {
	return ServiceError{Class: ClassDefinition, Code: CodeDefObjectUndefined, Specific: T(0xa8, undefined.Encode())}
}

// EnrollmentDeletion is a DeleteEventEnrollment request: specific names,
// or every enrollment of a condition or of an action.
type EnrollmentDeletion struct {
	Specific  []ObjectName
	Condition *ObjectName
	Action    *ObjectName
}

// DeleteEventEnrollmentRequest is the [58] request.
func DeleteEventEnrollmentRequest(d EnrollmentDeletion) []byte {
	switch {
	case d.Condition != nil:
		return svc(SvcDeleteEventEnrollment, T(0xa1, d.Condition.Encode()))
	case d.Action != nil:
		return svc(SvcDeleteEventEnrollment, T(0xa2, d.Action.Encode()))
	}
	return svc(SvcDeleteEventEnrollment, names(0xa0, d.Specific))
}

// DecodeDeleteEventEnrollment decodes a [58] request.
func DecodeDeleteEventEnrollment(body Elem) (EnrollmentDeletion, error) {
	in, _, err := Parse(body.Val)
	if err != nil {
		return EnrollmentDeletion{}, err
	}
	switch in.Tag {
	case 0xa0:
		ns, err := decodeNames(in)
		return EnrollmentDeletion{Specific: ns}, err
	case 0xa1, 0xa2:
		n, err := explicitName(in)
		if in.Tag == 0xa1 {
			return EnrollmentDeletion{Condition: &n}, err
		}
		return EnrollmentDeletion{Action: &n}, err
	}
	return EnrollmentDeletion{}, fmt.Errorf("mms: a delete event enrollment scope with tag %#x", in.Tag)
}

// DeleteEventEnrollmentResponse answers [58] with the candidates not
// deleted (and DeleteEventConditionResponse, DeleteEventActionResponse
// answer [48] and [54] likewise).
func DeleteEventEnrollmentResponse(notDeleted uint32) []byte {
	return unsignedResponse(SvcDeleteEventEnrollment, notDeleted)
}

// DeleteEventConditionResponse answers [48].
func DeleteEventConditionResponse(notDeleted uint32) []byte {
	return unsignedResponse(SvcDeleteEventCondition, notDeleted)
}

// DeleteEventActionResponse answers [54].
func DeleteEventActionResponse(notDeleted uint32) []byte {
	return unsignedResponse(SvcDeleteEventAction, notDeleted)
}

// EnrollmentChange is an AlterEventEnrollment request.
type EnrollmentChange struct {
	Name        ObjectName
	Transitions *BitString
	AckRule     *int
}

// AlterEventEnrollmentRequest is the [59] request.
func AlterEventEnrollmentRequest(c EnrollmentChange) []byte {
	parts := [][]byte{T(0xa0, c.Name.Encode())}
	if c.Transitions != nil {
		parts = append(parts, T(0x81, fixed(*c.Transitions, numTransitions).Contents()))
	}
	if c.AckRule != nil {
		parts = append(parts, Int(0x82, int64(*c.AckRule)))
	}
	return svc(SvcAlterEventEnrollment, parts...)
}

// DecodeAlterEventEnrollment decodes a [59] request.
func DecodeAlterEventEnrollment(body Elem) (EnrollmentChange, error) {
	f, err := fields(body)
	if err != nil {
		return EnrollmentChange{}, err
	}
	var c EnrollmentChange
	nm, ok := f[0]
	if !ok {
		return c, errors.New("mms: an alter event enrollment request without the name")
	}
	if c.Name, err = explicitName(nm); err != nil {
		return c, err
	}
	if e, ok := f[1]; ok {
		b, err := DecodeBitString(e.Val)
		if err != nil {
			return c, err
		}
		b = fixed(b, numTransitions)
		c.Transitions = &b
	}
	if e, ok := f[2]; ok {
		v := intOf(e)
		c.AckRule = &v
	}
	return c, nil
}

// AlterEventEnrollmentResponse answers [59]: the enrollment's state
// (EEUndefined for undefined) and the transition time.
func AlterEventEnrollmentResponse(state int, t EventTime) []byte {
	st := Int(0x80, int64(state))
	if state == EEUndefined {
		st = T(0x81)
	}
	return svc(SvcAlterEventEnrollment, T(0xa0, st), eventTime(0xa1, t))
}

// ReportEventEnrollmentStatusRequest is the [60] request.
func ReportEventEnrollmentStatusRequest(n ObjectName) []byte {
	return svc(SvcReportEventEnrollmentStatus, n.Encode())
}

// EventEnrollmentStatus is a ReportEventEnrollmentStatus response.
type EventEnrollmentStatus struct {
	Transitions      BitString
	NotificationLost bool
	Duration         int
	AckRule          *int
	State            int // EE-State
}

// EventEnrollmentStatusResponse answers [60].
func EventEnrollmentStatusResponse(s EventEnrollmentStatus) []byte {
	parts := [][]byte{T(0x80, fixed(s.Transitions, numTransitions).Contents())}
	if s.NotificationLost {
		parts = append(parts, Bool(0x81, true))
	}
	parts = append(parts, Int(0x82, int64(s.Duration)))
	if s.AckRule != nil {
		parts = append(parts, Int(0x83, int64(*s.AckRule)))
	}
	parts = append(parts, Int(0x84, int64(s.State)))
	return svc(SvcReportEventEnrollmentStatus, parts...)
}

func decodeEventEnrollmentStatus(body Elem) (EventEnrollmentStatus, error) {
	f, err := fields(body)
	if err != nil {
		return EventEnrollmentStatus{}, err
	}
	var s EventEnrollmentStatus
	tr, ok0 := f[0]
	du, ok2 := f[2]
	st, ok4 := f[4]
	if !ok0 || !ok2 || !ok4 {
		return s, errors.New("mms: an event enrollment status without a mandatory field")
	}
	if s.Transitions, err = DecodeBitString(tr.Val); err != nil {
		return s, err
	}
	s.Duration, s.State = intOf(du), intOf(st)
	if e, ok := f[1]; ok {
		s.NotificationLost = boolOf(e)
	}
	if e, ok := f[3]; ok {
		v := intOf(e)
		s.AckRule = &v
	}
	return s, nil
}

// Scopes of a GetEventEnrollmentAttributes request.
const (
	EEScopeSpecific  = 0
	EEScopeClient    = 1
	EEScopeCondition = 2
	EEScopeAction    = 3
)

// EnrollmentQuery is a GetEventEnrollmentAttributes request.
type EnrollmentQuery struct {
	Scope         int // EEScope…; EEScopeClient by default
	Names         []ObjectName
	Condition     *ObjectName
	Action        *ObjectName
	ContinueAfter *ObjectName
}

// GetEventEnrollmentAttributesRequest is the [61] request.
func GetEventEnrollmentAttributesRequest(q EnrollmentQuery) []byte {
	var parts [][]byte
	if q.Scope != EEScopeClient {
		parts = append(parts, Int(0x80, int64(q.Scope)))
	}
	if q.Scope == EEScopeSpecific {
		parts = append(parts, names(0xa1, q.Names))
	}
	if q.Condition != nil {
		parts = append(parts, T(0xa3, q.Condition.Encode()))
	}
	if q.Action != nil {
		parts = append(parts, T(0xa4, q.Action.Encode()))
	}
	if q.ContinueAfter != nil {
		parts = append(parts, T(0xa5, q.ContinueAfter.Encode()))
	}
	return svc(SvcGetEventEnrollmentAttributes, parts...)
}

// DecodeGetEventEnrollmentAttributes decodes a [61] request.
func DecodeGetEventEnrollmentAttributes(body Elem) (EnrollmentQuery, error) {
	f, err := fields(body)
	if err != nil {
		return EnrollmentQuery{}, err
	}
	q := EnrollmentQuery{Scope: EEScopeClient}
	if e, ok := f[0]; ok {
		q.Scope = intOf(e)
	}
	if e, ok := f[1]; ok {
		if q.Names, err = decodeNames(e); err != nil {
			return q, err
		}
	}
	for tag, dst := range map[int]**ObjectName{3: &q.Condition, 4: &q.Action, 5: &q.ContinueAfter} {
		if e, ok := f[tag]; ok {
			n, err := explicitName(e)
			if err != nil {
				return q, err
			}
			*dst = &n
		}
	}
	if q.Scope < EEScopeSpecific || q.Scope > EEScopeAction {
		return q, fmt.Errorf("mms: event enrollment scope %d", q.Scope)
	}
	return q, nil
}

// EEAttributes are one enrollment's attributes in a
// GetEventEnrollmentAttributes response.
type EEAttributes struct {
	Name ObjectName
	// Condition is nil when the condition is undefined.
	Condition *ObjectName
	// Action is the action; HasAction with a nil Action is undefined.
	Action    *ObjectName
	HasAction bool
	Deletable bool
	Class     int
	Duration  int
	InvokeID  *uint32
	// RemainingDelay is the modifier's remaining acceptable delay.
	RemainingDelay *uint32
}

func (a EEAttributes) encode() []byte {
	ec := T(0x81)
	if a.Condition != nil {
		ec = T(0xa0, a.Condition.Encode())
	}
	parts := [][]byte{T(0xa0, a.Name.Encode()), T(0xa1, ec)}
	if a.HasAction {
		ea := T(0x81)
		if a.Action != nil {
			ea = T(0xa0, a.Action.Encode())
		}
		parts = append(parts, T(0xa2, ea))
	}
	if a.Deletable {
		parts = append(parts, Bool(0x84, true))
	}
	parts = append(parts, Int(0x85, int64(a.Class)))
	if a.Duration != EECurrent {
		parts = append(parts, Int(0x86, int64(a.Duration)))
	}
	if a.InvokeID != nil {
		parts = append(parts, Uint(0x87, uint64(*a.InvokeID)))
	}
	if a.RemainingDelay != nil {
		parts = append(parts, Uint(0x88, uint64(*a.RemainingDelay)))
	}
	return T(0x30, parts...)
}

func decodeEEAttributes(e Elem) (EEAttributes, error) {
	f, err := fields(e)
	if err != nil {
		return EEAttributes{}, err
	}
	var a EEAttributes
	nm, ok0 := f[0]
	ec, ok1 := f[1]
	cl, ok5 := f[5]
	if !ok0 || !ok1 || !ok5 {
		return a, errors.New("mms: event enrollment attributes without a mandatory field")
	}
	if a.Name, err = explicitName(nm); err != nil {
		return a, err
	}
	choice := func(x Elem) (*ObjectName, error) {
		in, _, err := Parse(x.Val)
		if err != nil {
			return nil, err
		}
		if in.Tag == 0x81 {
			return nil, nil
		}
		n, err := explicitName(in)
		return &n, err
	}
	if a.Condition, err = choice(ec); err != nil {
		return a, err
	}
	if x, ok := f[2]; ok {
		a.HasAction = true
		if a.Action, err = choice(x); err != nil {
			return a, err
		}
	}
	if x, ok := f[4]; ok {
		a.Deletable = boolOf(x)
	}
	a.Class = intOf(cl)
	if x, ok := f[6]; ok {
		a.Duration = intOf(x)
	}
	if x, ok := f[7]; ok {
		v := uintOf(x)
		a.InvokeID = &v
	}
	if x, ok := f[8]; ok {
		v := uintOf(x)
		a.RemainingDelay = &v
	}
	return a, nil
}

// EventEnrollmentAttributesResponse answers [61].
func EventEnrollmentAttributesResponse(list []EEAttributes, more bool) []byte {
	items := make([][]byte, len(list))
	for i, a := range list {
		items[i] = a.encode()
	}
	parts := [][]byte{T(0xa0, items...)}
	if more {
		parts = append(parts, Bool(0x81, true))
	}
	return svc(SvcGetEventEnrollmentAttributes, parts...)
}

func decodeEEList(body Elem) ([]EEAttributes, bool, error) {
	f, err := fields(body)
	if err != nil {
		return nil, false, err
	}
	var out []EEAttributes
	if l, ok := f[0]; ok {
		kids, err := l.Children()
		if err != nil {
			return nil, false, err
		}
		for _, k := range kids {
			a, err := decodeEEAttributes(k)
			if err != nil {
				return nil, false, err
			}
			out = append(out, a)
		}
	}
	more := false
	if m, ok := f[1]; ok {
		more = boolOf(m)
	}
	return out, more, nil
}

// ---- event management (clause 18) -----------------------------------------

// Acknowledgement is an AcknowledgeEventNotification request.
type Acknowledgement struct {
	Enrollment ObjectName
	State      int // EC-State acknowledged
	Time       EventTime
}

// AcknowledgeEventNotificationRequest is the [62] request.
func AcknowledgeEventNotificationRequest(a Acknowledgement) []byte {
	return svc(SvcAcknowledgeEventNotification, T(0xa0, a.Enrollment.Encode()), Int(0x82, int64(a.State)),
		eventTime(0xa3, a.Time))
}

// DecodeAcknowledgeEventNotification decodes a [62] request.
func DecodeAcknowledgeEventNotification(body Elem) (Acknowledgement, error) {
	f, err := fields(body)
	if err != nil {
		return Acknowledgement{}, err
	}
	var a Acknowledgement
	nm, ok0 := f[0]
	st, ok2 := f[2]
	tm, ok3 := f[3]
	if !ok0 || !ok2 || !ok3 {
		return a, errors.New("mms: an acknowledgement without a mandatory field")
	}
	if a.Enrollment, err = explicitName(nm); err != nil {
		return a, err
	}
	a.State = intOf(st)
	a.Time, err = decodeEventTime(tm)
	return a, err
}

// AlarmQuery is a GetAlarmSummary or GetAlarmEnrollmentSummary request.
type AlarmQuery struct {
	EnrollmentsOnly bool // default true
	ActiveOnly      bool // default true
	AckFilter       int  // AckFilter…, default not-acked
	MostSevere      int  // default 0
	LeastSevere     int  // default 127
	ContinueAfter   *ObjectName
}

// DefaultAlarmQuery is the request with every default.
var DefaultAlarmQuery = AlarmQuery{EnrollmentsOnly: true, ActiveOnly: true, AckFilter: AckFilterNotAcked, LeastSevere: 127}

func (q AlarmQuery) encode(num int) []byte {
	var parts [][]byte
	if !q.EnrollmentsOnly {
		parts = append(parts, Bool(0x80, false))
	}
	if !q.ActiveOnly {
		parts = append(parts, Bool(0x81, false))
	}
	if q.AckFilter != AckFilterNotAcked {
		parts = append(parts, Int(0x82, int64(q.AckFilter)))
	}
	if q.MostSevere != 0 || q.LeastSevere != 127 {
		parts = append(parts, T(0xa3, Uint(0x80, uint64(q.MostSevere)), Uint(0x81, uint64(q.LeastSevere))))
	}
	if q.ContinueAfter != nil {
		parts = append(parts, T(0xa5, q.ContinueAfter.Encode()))
	}
	return svc(num, parts...)
}

// GetAlarmSummaryRequest is the [63] request.
func GetAlarmSummaryRequest(q AlarmQuery) []byte { return q.encode(SvcGetAlarmSummary) }

// GetAlarmEnrollmentSummaryRequest is the [64] request.
func GetAlarmEnrollmentSummaryRequest(q AlarmQuery) []byte {
	return q.encode(SvcGetAlarmEnrollmentSummary)
}

// DecodeAlarmQuery decodes a [63] or [64] request.
func DecodeAlarmQuery(body Elem) (AlarmQuery, error) {
	f, err := fields(body)
	if err != nil {
		return AlarmQuery{}, err
	}
	q := DefaultAlarmQuery
	if e, ok := f[0]; ok {
		q.EnrollmentsOnly = boolOf(e)
	}
	if e, ok := f[1]; ok {
		q.ActiveOnly = boolOf(e)
	}
	if e, ok := f[2]; ok {
		q.AckFilter = intOf(e)
	}
	if e, ok := f[3]; ok {
		sf, err := fields(e)
		if err != nil {
			return q, err
		}
		if x, ok := sf[0]; ok {
			q.MostSevere = intOf(x)
		}
		if x, ok := sf[1]; ok {
			q.LeastSevere = intOf(x)
		}
	}
	if e, ok := f[5]; ok {
		n, err := explicitName(e)
		if err != nil {
			return q, err
		}
		q.ContinueAfter = &n
	}
	if q.AckFilter < AckFilterNotAcked || q.AckFilter > AckFilterAll {
		return q, fmt.Errorf("mms: acknowledgement filter %d", q.AckFilter)
	}
	return q, nil
}

// AlarmSummary is one monitored condition in a GetAlarmSummary response.
type AlarmSummary struct {
	Condition    ObjectName
	Severity     int
	State        int
	Unacked      int // Unacked…
	TimeToActive EventTime
	TimeToIdle   EventTime
}

// AlarmSummaryResponse answers [63].
func AlarmSummaryResponse(list []AlarmSummary, more bool) []byte {
	items := make([][]byte, len(list))
	for i, a := range list {
		parts := [][]byte{T(0xa0, a.Condition.Encode()), Uint(0x81, uint64(a.Severity)), Int(0x82, int64(a.State)),
			Int(0x83, int64(a.Unacked))}
		if a.TimeToActive.Defined() {
			parts = append(parts, eventTime(0xa5, a.TimeToActive))
		}
		if a.TimeToIdle.Defined() {
			parts = append(parts, eventTime(0xa6, a.TimeToIdle))
		}
		items[i] = T(0x30, parts...)
	}
	parts := [][]byte{T(0xa0, items...)}
	if more {
		parts = append(parts, Bool(0x81, true))
	}
	return svc(SvcGetAlarmSummary, parts...)
}

func decodeAlarmSummaries(body Elem) ([]AlarmSummary, bool, error) {
	f, err := fields(body)
	if err != nil {
		return nil, false, err
	}
	var out []AlarmSummary
	if l, ok := f[0]; ok {
		kids, err := l.Children()
		if err != nil {
			return nil, false, err
		}
		for _, k := range kids {
			g, err := fields(k)
			if err != nil {
				return nil, false, err
			}
			var a AlarmSummary
			nm, ok0 := g[0]
			sv, ok1 := g[1]
			st, ok2 := g[2]
			un, ok3 := g[3]
			if !ok0 || !ok1 || !ok2 || !ok3 {
				return nil, false, errors.New("mms: an alarm summary without a mandatory field")
			}
			if a.Condition, err = explicitName(nm); err != nil {
				return nil, false, err
			}
			a.Severity, a.State, a.Unacked = intOf(sv), intOf(st), intOf(un)
			if x, ok := g[5]; ok {
				if a.TimeToActive, err = decodeEventTime(x); err != nil {
					return nil, false, err
				}
			}
			if x, ok := g[6]; ok {
				if a.TimeToIdle, err = decodeEventTime(x); err != nil {
					return nil, false, err
				}
			}
			out = append(out, a)
		}
	}
	more := false
	if m, ok := f[1]; ok {
		more = boolOf(m)
	}
	return out, more, nil
}

// AlarmEnrollmentSummary is one enrollment in a GetAlarmEnrollmentSummary
// response.
type AlarmEnrollmentSummary struct {
	Enrollment       ObjectName
	Severity         int
	State            int // EC-State of the condition
	NotificationLost bool
	AckRule          int
	EEState          *int
	TimeToActive     EventTime
	TimeActiveAck    EventTime
	TimeToIdle       EventTime
	TimeIdleAck      EventTime
}

// AlarmEnrollmentSummaryResponse answers [64].
func AlarmEnrollmentSummaryResponse(list []AlarmEnrollmentSummary, more bool) []byte {
	items := make([][]byte, len(list))
	for i, a := range list {
		parts := [][]byte{T(0xa0, a.Enrollment.Encode()), Uint(0x83, uint64(a.Severity)), Int(0x84, int64(a.State))}
		if a.NotificationLost {
			parts = append(parts, Bool(0x86, true))
		}
		parts = append(parts, Int(0x87, int64(a.AckRule)))
		if a.EEState != nil {
			parts = append(parts, Int(0x88, int64(*a.EEState)))
		}
		for i, t := range []EventTime{a.TimeToActive, a.TimeActiveAck, a.TimeToIdle, a.TimeIdleAck} {
			if t.Defined() {
				parts = append(parts, eventTime(0xa9+byte(i), t))
			}
		}
		items[i] = T(0x30, parts...)
	}
	parts := [][]byte{T(0xa0, items...)}
	if more {
		parts = append(parts, Bool(0x81, true))
	}
	return svc(SvcGetAlarmEnrollmentSummary, parts...)
}

func decodeAlarmEnrollmentSummaries(body Elem) ([]AlarmEnrollmentSummary, bool, error) {
	f, err := fields(body)
	if err != nil {
		return nil, false, err
	}
	var out []AlarmEnrollmentSummary
	if l, ok := f[0]; ok {
		kids, err := l.Children()
		if err != nil {
			return nil, false, err
		}
		for _, k := range kids {
			g, err := fields(k)
			if err != nil {
				return nil, false, err
			}
			var a AlarmEnrollmentSummary
			nm, ok0 := g[0]
			sv, ok3 := g[3]
			st, ok4 := g[4]
			ar, ok7 := g[7]
			if !ok0 || !ok3 || !ok4 || !ok7 {
				return nil, false, errors.New("mms: an alarm enrollment summary without a mandatory field")
			}
			if a.Enrollment, err = explicitName(nm); err != nil {
				return nil, false, err
			}
			a.Severity, a.State, a.AckRule = intOf(sv), intOf(st), intOf(ar)
			if x, ok := g[6]; ok {
				a.NotificationLost = boolOf(x)
			}
			if x, ok := g[8]; ok {
				v := intOf(x)
				a.EEState = &v
			}
			for i, dst := range []*EventTime{&a.TimeToActive, &a.TimeActiveAck, &a.TimeToIdle, &a.TimeIdleAck} {
				if x, ok := g[9+i]; ok {
					if *dst, err = decodeEventTime(x); err != nil {
						return nil, false, err
					}
				}
			}
			out = append(out, a)
		}
	}
	more := false
	if m, ok := f[1]; ok {
		more = boolOf(m)
	}
	return out, more, nil
}

// ---- client calls -------------------------------------------------------------

func (c *Client) callNull(ctx context.Context, req []byte, num int) error {
	_, err := c.call(ctx, req, num)
	return err
}

func (c *Client) callUnsigned(ctx context.Context, req []byte, num int) (uint32, error) {
	body, err := c.call(ctx, req, num)
	if err != nil {
		return 0, err
	}
	v, err := DecodeUint(body.Val)
	return uint32(v), err
}

// DefineEventCondition defines an event condition at the server.
func (c *Client) DefineEventCondition(ctx context.Context, d EventConditionDef) error {
	return c.callNull(ctx, DefineEventConditionRequest(d), SvcDefineEventCondition)
}

// DeleteEventCondition deletes event conditions and returns how many
// candidates were not deleted.
func (c *Client) DeleteEventCondition(ctx context.Context, s DeleteScope) (uint32, error) {
	return c.callUnsigned(ctx, DeleteEventConditionRequest(s), SvcDeleteEventCondition)
}

// GetEventConditionAttributes returns an event condition's attributes.
func (c *Client) GetEventConditionAttributes(ctx context.Context, n ObjectName) (EventConditionAttrs, error) {
	body, err := c.call(ctx, GetEventConditionAttributesRequest(n), SvcGetEventConditionAttributes)
	if err != nil {
		return EventConditionAttrs{}, err
	}
	return decodeEventConditionAttrs(body)
}

// ReportEventConditionStatus returns an event condition's status.
func (c *Client) ReportEventConditionStatus(ctx context.Context, n ObjectName) (EventConditionStatus, error) {
	body, err := c.call(ctx, ReportEventConditionStatusRequest(n), SvcReportEventConditionStatus)
	if err != nil {
		return EventConditionStatus{}, err
	}
	return decodeEventConditionStatus(body)
}

// AlterEventConditionMonitoring changes how a condition is monitored.
func (c *Client) AlterEventConditionMonitoring(ctx context.Context, m ConditionMonitoring) error {
	return c.callNull(ctx, AlterEventConditionMonitoringRequest(m), SvcAlterEventConditionMonitoring)
}

// TriggerEvent triggers a network-triggered event condition.
func (c *Client) TriggerEvent(ctx context.Context, n ObjectName, priority *int) error {
	return c.callNull(ctx, TriggerEventRequest(n, priority), SvcTriggerEvent)
}

// DefineEventAction defines an event action.
func (c *Client) DefineEventAction(ctx context.Context, d EventActionDef) error {
	return c.callNull(ctx, DefineEventActionRequest(d), SvcDefineEventAction)
}

// DeleteEventAction deletes event actions and returns how many candidates
// were not deleted.
func (c *Client) DeleteEventAction(ctx context.Context, s DeleteScope) (uint32, error) {
	return c.callUnsigned(ctx, DeleteEventActionRequest(s), SvcDeleteEventAction)
}

// GetEventActionAttributes returns an event action's attributes.
func (c *Client) GetEventActionAttributes(ctx context.Context, n ObjectName) (EventActionAttrs, error) {
	body, err := c.call(ctx, GetEventActionAttributesRequest(n), SvcGetEventActionAttributes)
	if err != nil {
		return EventActionAttrs{}, err
	}
	return decodeEventActionAttrs(body)
}

// ReportEventActionStatus returns the number of enrollments referring to
// an event action.
func (c *Client) ReportEventActionStatus(ctx context.Context, n ObjectName) (uint32, error) {
	return c.callUnsigned(ctx, ReportEventActionStatusRequest(n), SvcReportEventActionStatus)
}

// DefineEventEnrollment enrolls this association for transitions of an
// event condition.
func (c *Client) DefineEventEnrollment(ctx context.Context, d EventEnrollmentDef) error {
	return c.callNull(ctx, DefineEventEnrollmentRequest(d), SvcDefineEventEnrollment)
}

// DeleteEventEnrollment deletes enrollments and returns how many candidates
// were not deleted.
func (c *Client) DeleteEventEnrollment(ctx context.Context, d EnrollmentDeletion) (uint32, error) {
	return c.callUnsigned(ctx, DeleteEventEnrollmentRequest(d), SvcDeleteEventEnrollment)
}

// AlterEventEnrollment changes an enrollment and returns its state and the
// transition time.
func (c *Client) AlterEventEnrollment(ctx context.Context, ch EnrollmentChange) (int, EventTime, error) {
	body, err := c.call(ctx, AlterEventEnrollmentRequest(ch), SvcAlterEventEnrollment)
	if err != nil {
		return 0, EventTime{}, err
	}
	f, err := fields(body)
	if err != nil {
		return 0, EventTime{}, err
	}
	st, ok0 := f[0]
	tm, ok1 := f[1]
	if !ok0 || !ok1 {
		return 0, EventTime{}, errors.New("mms: an alter event enrollment response without a mandatory field")
	}
	in, _, err := Parse(st.Val)
	if err != nil {
		return 0, EventTime{}, err
	}
	state := EEUndefined
	if in.Tag == 0x80 {
		state = intOf(in)
	}
	t, err := decodeEventTime(tm)
	return state, t, err
}

// ReportEventEnrollmentStatus returns an enrollment's status.
func (c *Client) ReportEventEnrollmentStatus(ctx context.Context, n ObjectName) (EventEnrollmentStatus, error) {
	body, err := c.call(ctx, ReportEventEnrollmentStatusRequest(n), SvcReportEventEnrollmentStatus)
	if err != nil {
		return EventEnrollmentStatus{}, err
	}
	return decodeEventEnrollmentStatus(body)
}

// GetEventEnrollmentAttributes lists enrollments' attributes, following
// continuation.
func (c *Client) GetEventEnrollmentAttributes(ctx context.Context, q EnrollmentQuery) ([]EEAttributes, error) {
	var out []EEAttributes
	for range 1000 {
		body, err := c.call(ctx, GetEventEnrollmentAttributesRequest(q), SvcGetEventEnrollmentAttributes)
		if err != nil {
			return nil, err
		}
		list, more, err := decodeEEList(body)
		if err != nil {
			return nil, err
		}
		out = append(out, list...)
		if !more || len(list) == 0 {
			return out, nil
		}
		last := list[len(list)-1].Name
		q.ContinueAfter = &last
	}
	return nil, errors.New("mms: the enrollment list does not end")
}

// AcknowledgeEventNotification acknowledges a notification.
func (c *Client) AcknowledgeEventNotification(ctx context.Context, a Acknowledgement) error {
	return c.callNull(ctx, AcknowledgeEventNotificationRequest(a), SvcAcknowledgeEventNotification)
}

// Acknowledge acknowledges a received notification (its enrollment,
// state and transition time).
func (c *Client) Acknowledge(ctx context.Context, n EventNotification) error {
	return c.AcknowledgeEventNotification(ctx, Acknowledgement{Enrollment: n.Enrollment, State: n.State, Time: n.EventTime()})
}

// GetAlarmSummary returns the alarm summary, following continuation.
func (c *Client) GetAlarmSummary(ctx context.Context, q AlarmQuery) ([]AlarmSummary, error) {
	var out []AlarmSummary
	for range 1000 {
		body, err := c.call(ctx, GetAlarmSummaryRequest(q), SvcGetAlarmSummary)
		if err != nil {
			return nil, err
		}
		list, more, err := decodeAlarmSummaries(body)
		if err != nil {
			return nil, err
		}
		out = append(out, list...)
		if !more || len(list) == 0 {
			return out, nil
		}
		last := list[len(list)-1].Condition
		q.ContinueAfter = &last
	}
	return nil, errors.New("mms: the alarm summary does not end")
}

// GetAlarmEnrollmentSummary returns the alarm enrollment summary,
// following continuation.
func (c *Client) GetAlarmEnrollmentSummary(ctx context.Context, q AlarmQuery) ([]AlarmEnrollmentSummary, error) {
	var out []AlarmEnrollmentSummary
	for range 1000 {
		body, err := c.call(ctx, GetAlarmEnrollmentSummaryRequest(q), SvcGetAlarmEnrollmentSummary)
		if err != nil {
			return nil, err
		}
		list, more, err := decodeAlarmEnrollmentSummaries(body)
		if err != nil {
			return nil, err
		}
		out = append(out, list...)
		if !more || len(list) == 0 {
			return out, nil
		}
		last := list[len(list)-1].Enrollment
		q.ContinueAfter = &last
	}
	return nil, errors.New("mms: the alarm enrollment summary does not end")
}
