package mms

import (
	"sync"
	"testing"
	"time"
)

type sink struct {
	mu  sync.Mutex
	got map[any][]EventNotification
}

func (s *sink) send(assoc any, n EventNotification) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.got == nil {
		s.got = map[any][]EventNotification{}
	}
	s.got[assoc] = append(s.got[assoc], n)
	return nil
}

func (s *sink) take(assoc any) []EventNotification {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.got[assoc]
	delete(s.got, assoc)
	return out
}

func request(t *testing.T, service []byte) Request {
	t.Helper()
	e := mustParse(t, service)
	return Request{Service: e.Num, Body: e}
}

func handleOK(t *testing.T, m *EventManager, assoc any, service []byte) Elem {
	t.Helper()
	o := m.Handle(assoc, request(t, service))
	if o.Reject || o.Error != nil {
		t.Fatalf("request %x: reject %v, error %v", service, o.Reject, o.Error)
	}
	if o.Deliver != nil {
		o.Deliver()
	}
	return mustParse(t, o.Response)
}

// The Procedure for Event Transition Processing (ISO 9506-1:2003 18.1.1)
// and the enrollment state machines (21.1.2, Figures 21 to 24): an
// enrollment is notified of the transitions it asked for, with the
// condition's severity, state, transition time and its acknowledgement
// rule; acknowledgements follow 18.4.2.3 (arc 6 accepted, findings F-692).
// Covers: SIG-IPE-1760, SIG-IPE-1762
func TestEventManagerTransitionsAndAcknowledgement(t *testing.T) {
	s := &sink{}
	m := &EventManager{Send: s.send}
	yes := true
	cond := DomainName("D", "Data_failure")
	if err := m.DefineCondition(EventConditionDef{Name: cond, Class: ECMonitored, Priority: 64, Severity: 10, AlarmSummaryReports: &yes}); err != nil {
		t.Fatal(err)
	}
	a, b := "assoc-a", "assoc-b"
	all := Transitions(TransIdleToActive, TransDisabledToActive, TransActiveToIdle, TransDisabledToIdle)
	eeA := ObjectName{Scope: ScopeAA, Item: "EA"}
	handleOK(t, m, a, DefineEventEnrollmentRequest(EventEnrollmentDef{Name: eeA, Condition: cond, Transitions: all, AckRule: AckAll}))
	eeB := DomainName("D", "EB")
	handleOK(t, m, b, DefineEventEnrollmentRequest(EventEnrollmentDef{Name: eeB, Condition: cond, Transitions: Transitions(TransIdleToActive), AckRule: AckNone}))
	// A rule other than none needs the transitions to active.
	o := m.Handle(a, request(t, DefineEventEnrollmentRequest(EventEnrollmentDef{Name: ObjectName{Scope: ScopeAA, Item: "X"}, Condition: cond,
		Transitions: Transitions(TransActiveToIdle), AckRule: AckSimple})))
	if o.Error == nil || o.Error.Class != ClassDefinition || o.Error.Code != CodeDefAttrInconsistent {
		t.Errorf("inconsistent transitions = %+v", o)
	}
	t1 := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	if err := m.Transition(cond, ECStateActive, t1); err != nil {
		t.Fatal(err)
	}
	na, nb := s.take(a), s.take(b)
	if len(na) != 1 || len(nb) != 1 {
		t.Fatalf("notifications %d, %d", len(na), len(nb))
	}
	if n := na[0]; n.Enrollment != eeA || n.Condition != cond || n.Severity != 10 || n.State != ECStateActive || !n.Time.Equal(t1) ||
		!n.HasAckRule || n.AckRule != AckAll {
		t.Errorf("notification = %+v", n)
	}
	status := func(assoc any, n ObjectName) EventEnrollmentStatus {
		st, err := decodeEventEnrollmentStatus(handleOK(t, m, assoc, ReportEventEnrollmentStatusRequest(n)))
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	if st := status(a, eeA); st.State != EEActiveNoAckA || *st.AckRule != AckAll || st.Duration != EECurrent {
		t.Errorf("after active = %+v", st)
	}
	if st := status(b, eeB); st.State != EEActive || st.Duration != EEPermanent {
		t.Errorf("rule none after active = %+v", st)
	}
	// The alarm summary sees one unacknowledged enrollment.
	sums, _, err := decodeAlarmSummaries(handleOK(t, m, a, GetAlarmSummaryRequest(DefaultAlarmQuery)))
	if err != nil || len(sums) != 1 || sums[0].Unacked != UnackedActive || sums[0].Severity != 10 || !sums[0].TimeToActive.Time.Equal(t1) {
		t.Errorf("alarm summary = %+v %v", sums, err)
	}
	// Acknowledging with the wrong time changes nothing; the right one
	// acknowledges (arc 5).
	handleOK(t, m, a, AcknowledgeEventNotificationRequest(Acknowledgement{Enrollment: eeA, State: ECStateActive, Time: EventTime{Time: t1.Add(time.Second)}}))
	if st := status(a, eeA); st.State != EEActiveNoAckA {
		t.Errorf("after a wrong acknowledgement = %d", st.State)
	}
	handleOK(t, m, a, AcknowledgeEventNotificationRequest(Acknowledgement{Enrollment: eeA, State: ECStateActive, Time: na[0].EventTime()}))
	if st := status(a, eeA); st.State != EEActiveAcked {
		t.Errorf("after acknowledging active = %d", st.State)
	}
	sums, _, _ = decodeAlarmSummaries(handleOK(t, m, a, GetAlarmSummaryRequest(DefaultAlarmQuery)))
	if len(sums) != 0 {
		t.Errorf("not-acked summary after the acknowledgement = %+v", sums)
	}
	t2 := t1.Add(time.Minute)
	_ = m.Transition(cond, ECStateIdle, t2)
	if n := s.take(a); len(n) != 1 || n[0].State != ECStateIdle {
		t.Errorf("idle notifications for ack-all = %+v", n)
	}
	if n := s.take(b); len(n) != 0 {
		t.Errorf("idle notification sent to an enrollment without that transition: %+v", n)
	}
	if st := status(a, eeA); st.State != EEIdleNoAckI {
		t.Errorf("ack-all after idle = %d", st.State)
	}
	handleOK(t, m, a, AcknowledgeEventNotificationRequest(Acknowledgement{Enrollment: eeA, State: ECStateIdle, Time: EventTime{Time: t2}}))
	if st := status(a, eeA); st.State != EEIdleAcked {
		t.Errorf("ack-all after acknowledging idle = %d", st.State)
	}
	// Arc 6: the active transition acknowledged after the condition went
	// idle.
	_ = m.Transition(cond, ECStateActive, t2.Add(time.Minute))
	_ = m.Transition(cond, ECStateIdle, t2.Add(2*time.Minute))
	if st := status(a, eeA); st.State != EEIdleNoAckA {
		t.Errorf("ack-all active then idle unacknowledged = %d", st.State)
	}
	handleOK(t, m, a, AcknowledgeEventNotificationRequest(Acknowledgement{Enrollment: eeA, State: ECStateActive, Time: EventTime{Time: t2.Add(time.Minute)}}))
	if st := status(a, eeA); st.State != EEIdleNoAckI {
		t.Errorf("arc 6 = %d", st.State)
	}
	aes, _, err := decodeAlarmEnrollmentSummaries(handleOK(t, m, a, GetAlarmEnrollmentSummaryRequest(AlarmQuery{EnrollmentsOnly: true, AckFilter: AckFilterAll, LeastSevere: 127})))
	if err != nil || len(aes) != 1 || aes[0].Enrollment != eeA || *aes[0].EEState != EEIdleNoAckI || !aes[0].TimeActiveAck.Defined() {
		t.Errorf("alarm enrollment summary = %+v %v", aes, err)
	}
	// Disabling notifies transitions to disabled only to enrollments that
	// asked; conditions report their status.
	no := false
	handleOK(t, m, a, AlterEventConditionMonitoringRequest(ConditionMonitoring{Name: cond, Enabled: &no}))
	st, err := decodeEventConditionStatus(handleOK(t, m, a, ReportEventConditionStatusRequest(cond)))
	if err != nil || st.State != ECStateDisabled || *st.Enabled || st.NumEnrollments != 2 {
		t.Errorf("condition status = %+v %v", st, err)
	}
	if err := m.Transition(cond, ECStateActive, time.Now()); err == nil {
		t.Error("a disabled condition took a transition")
	}
	// The association's AA-specific enrollment ends with it.
	m.Release(a)
	if !m.HasEnrollment(cond, b) || m.HasEnrollment(cond, a) {
		t.Error("release did not remove only the AA-specific enrollment")
	}
}

// The event services of the manager (ISO 9506-1:2003 clauses 19 to 21):
// definitions and their errors (object exists, undefined condition with
// the service-specific information), deletion scopes and candidates not
// deleted, attributes, network-triggered conditions and TriggerEvent,
// event actions executed on a transition with the result in the
// notification, and any-to-deleted.
// Covers: SIG-IPE-1761
func TestEventManagerServices(t *testing.T) {
	s := &sink{}
	var execs int
	m := &EventManager{Send: s.send, Exec: func(assoc any, service []byte) ([]byte, *ServiceError) {
		execs++
		if e := mustParse(t, service); e.Num != SvcRead {
			return nil, &ServiceError{Class: ClassService, Code: 0}
		}
		return ReadResponse([]AccessResult{{Data: Integer(42)}}), nil
	}, Visible: func(assoc any, n ObjectName) bool { return n.Scope != ScopeDomain || n.Domain == "D" }}
	a := "a"
	local := VMDName("Local")
	_ = m.DefineCondition(EventConditionDef{Name: local, Class: ECMonitored, Priority: 64, Severity: 64})
	nt := DomainName("D", "NT")
	handleOK(t, m, a, DefineEventConditionRequest(EventConditionDef{Name: nt, Class: ECNetworkTriggered, Priority: 64, Severity: 1}))
	if o := m.Handle(a, request(t, DefineEventConditionRequest(EventConditionDef{Name: nt, Class: ECNetworkTriggered, Priority: 64, Severity: 1}))); o.Error == nil || o.Error.Code != CodeDefObjectExists {
		t.Errorf("duplicate = %+v", o)
	}
	if o := m.Handle(a, request(t, DefineEventConditionRequest(EventConditionDef{Name: DomainName("Other", "X"), Class: ECNetworkTriggered, Priority: 64, Severity: 64}))); o.Error == nil || o.Error.Class != ClassAccess {
		t.Errorf("invisible domain = %+v", o)
	}
	if o := m.Handle(a, request(t, DefineEventConditionRequest(EventConditionDef{Name: VMDName("M"), Class: ECMonitored, Priority: 64, Severity: 64, Monitored: &local}))); o.Error == nil {
		t.Errorf("monitored variable without a reader = %+v", o)
	}
	ga, err := decodeEventConditionAttrs(handleOK(t, m, a, GetEventConditionAttributesRequest(nt)))
	if err != nil || !ga.Deletable || ga.Class != ECNetworkTriggered || ga.Severity != 1 || ga.Monitored != nil || ga.MonitoredUndefined {
		t.Errorf("attributes = %+v %v", ga, err)
	}
	ga, _ = decodeEventConditionAttrs(handleOK(t, m, a, GetEventConditionAttributesRequest(local)))
	if ga.Deletable || !ga.MonitoredUndefined {
		t.Errorf("local attributes = %+v", ga)
	}
	undef := DomainName("D", "Nope")
	o := m.Handle(a, request(t, DefineEventEnrollmentRequest(EventEnrollmentDef{Name: DomainName("D", "E0"), Condition: undef, Transitions: Transitions()})))
	if o.Error == nil || o.Error.Code != CodeDefObjectUndefined || hexOf(o.Error.Specific) != hexOf(T(0xa8, undef.Encode())) {
		t.Errorf("undefined condition = %+v", o)
	}
	act := DomainName("D", "Act")
	handleOK(t, m, a, DefineEventActionRequest(EventActionDef{Name: act, Service: ReadRequest(VariableSpec{Vars: []ObjectName{VMDName("X")}})}))
	ee := DomainName("D", "E1")
	handleOK(t, m, a, DefineEventEnrollmentRequest(EventEnrollmentDef{Name: ee, Condition: nt, Transitions: Transitions(TransIdleToActive, TransAnyToDeleted), Action: &act}))
	if n, err := DecodeUint(handleOK(t, m, a, ReportEventActionStatusRequest(act)).Val); err != nil || n != 1 {
		t.Errorf("action status = %d %v", n, err)
	}
	// TriggerEvent on a network-triggered condition; not on a monitored one.
	handleOK(t, m, a, TriggerEventRequest(nt, nil))
	got := s.take(a)
	if len(got) != 1 || got[0].State != ECStateDisabled || got[0].HasAckRule || got[0].Action == nil || !got[0].Action.Success || execs != 1 {
		t.Fatalf("triggered notification = %+v, execs %d", got, execs)
	}
	if res, err := decodeReadResponse(mustParse(t, got[0].Action.Response)); err != nil || res[0].Data.Int != 42 {
		t.Errorf("action result = %+v %v", res, err)
	}
	if o := m.Handle(a, request(t, TriggerEventRequest(local, nil))); o.Error == nil || o.Error.Class != ClassService {
		t.Errorf("trigger of a monitored condition = %+v", o)
	}
	// The network-triggered enrollment's transitions are the empty set.
	st, _ := decodeEventEnrollmentStatus(handleOK(t, m, a, ReportEventEnrollmentStatusRequest(ee)))
	if st.Transitions.Get(TransIdleToActive) || st.AckRule != nil {
		t.Errorf("network-triggered enrollment status = %+v", st)
	}
	list, more, _ := decodeEEList(handleOK(t, m, a, GetEventEnrollmentAttributesRequest(EnrollmentQuery{Scope: EEScopeCondition, Condition: &nt})))
	if more || len(list) != 1 || list[0].Name != ee || *list[0].Action != act || !list[0].Deletable {
		t.Errorf("enrollment attributes = %+v", list)
	}
	// The action is referenced: not deleted. The local condition is not
	// deletable; the defined one is. Its enrollment is not told: an
	// enrollment on a network-triggered condition has the empty set of
	// transitions, any-to-deleted included (21.1.1.5).
	if n, _ := DecodeUint(handleOK(t, m, a, DeleteEventActionRequest(DeleteScope{Specific: []ObjectName{act}})).Val); n != 1 {
		t.Errorf("referenced action deleted (%d not deleted)", n)
	}
	if n, _ := DecodeUint(handleOK(t, m, a, DeleteEventConditionRequest(DeleteScope{VMD: true})).Val); n != 1 {
		t.Errorf("local condition: %d not deleted", n)
	}
	if n, _ := DecodeUint(handleOK(t, m, a, DeleteEventConditionRequest(DeleteScope{Domain: "D"})).Val); n != 0 {
		t.Errorf("domain conditions: %d not deleted", n)
	}
	if got = s.take(a); len(got) != 0 {
		t.Errorf("any-to-deleted on a network-triggered condition = %+v", got)
	}
	if o := m.Handle(a, request(t, GetEventConditionAttributesRequest(nt))); o.Error == nil || o.Error.Code != CodeDefObjectUndefined {
		t.Errorf("deleted condition = %+v", o)
	}
	list, _, _ = decodeEEList(handleOK(t, m, a, GetEventEnrollmentAttributesRequest(EnrollmentQuery{Scope: EEScopeClient})))
	if len(list) != 1 || list[0].Condition != nil {
		t.Errorf("enrollment of a deleted condition = %+v", list)
	}
	if n, _ := DecodeUint(handleOK(t, m, a, DeleteEventEnrollmentRequest(EnrollmentDeletion{Action: &act})).Val); n != 0 {
		t.Errorf("enrollments by action: %d not deleted", n)
	}
	if n, _ := DecodeUint(handleOK(t, m, a, DeleteEventActionRequest(DeleteScope{Domain: "D"})).Val); n != 0 {
		t.Errorf("unreferenced action: %d not deleted", n)
	}
	if o := m.Handle(a, request(t, TH(0xa0, SvcDefineEventEnrollment, T(0x80)))); !o.Reject {
		t.Errorf("a malformed request = %+v", o)
	}
}
