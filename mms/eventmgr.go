package mms

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// EventManager is the server side of MMS event management (ISO 9506-1:2003
// clauses 18 to 21) for any MMS server of ours: event conditions, event
// actions and notification event enrollments, the Procedure for Event
// Transition Processing (18.1.1), acknowledgement (18.4.2.3) with the
// enrollment state machines (21.1.2), the alarm summaries and the
// services that manage the objects. A server passes the event services'
// requests to Handle, reports its own condition transitions with
// Transition or Trigger, and calls Release when an association ends.
//
// Not offered: third-party enrollments (tpy), modifier enrollments
// (attachToEventCondition), event condition lists, access control lists,
// display enhancements, and event actions with modifiers.
type EventManager struct {
	// Send delivers a notification to an association; an error marks the
	// enrollment's notification lost. Called without the manager's lock.
	Send func(assoc any, n EventNotification) error
	// Exec executes an event action's confirmed service request on behalf
	// of the enrollment's association, returning the service's response
	// element or its error. Nil refuses the definition of event actions.
	Exec func(assoc any, service []byte) ([]byte, *ServiceError)
	// Visible reports whether an association may use an object name (a
	// bilateral table, a domain's existence); nil allows every name.
	Visible func(assoc any, n ObjectName) bool
	// MonitoredValue reads a boolean variable a monitored condition
	// refers to; nil refuses monitored conditions with a variable.
	MonitoredValue func(n ObjectName) (bool, error)
	// PageSize bounds the lists of one response (default 50).
	PageSize int

	mu      sync.Mutex
	conds   map[objKey]*eventCondition
	actions map[objKey]*eventAction
	enrolls map[objKey]*eventEnrollment
}

type objKey struct {
	scope        Scope
	domain, item string
	owner        any // the defining association, for AA-specific names
}

func keyOf(n ObjectName, assoc any) objKey {
	k := objKey{scope: n.Scope, domain: n.Domain, item: n.Item}
	if n.Scope == ScopeAA {
		k.owner = assoc
	}
	return k
}

type eventCondition struct {
	name                ObjectName
	owner               any
	class               int
	priority, severity  int
	state               int
	enabled             bool
	alarmSummaryReports bool
	monitored           *ObjectName
	evalInterval        *uint32
	deletable           bool
	toActive, toIdle    EventTime
	enrollments         []*eventEnrollment
}

type eventAction struct {
	name      ObjectName
	owner     any
	service   []byte
	deletable bool
	refs      int
}

type eventEnrollment struct {
	name        ObjectName
	owner       any
	client      any // nil once the association has ended
	cond        *eventCondition
	action      *eventAction
	hasAction   bool
	transitions BitString
	ackRule     int
	state       int // EE-State
	lost        bool
	activeAck   EventTime // when the last acknowledgements arrived
	idleAck     EventTime
	ackedActive EventTime // the transition times they acknowledged
	ackedIdle   EventTime
	duration    int
}

func (m *EventManager) init() {
	if m.conds == nil {
		m.conds = map[objKey]*eventCondition{}
		m.actions = map[objKey]*eventAction{}
		m.enrolls = map[objKey]*eventEnrollment{}
	}
}

func (m *EventManager) visible(assoc any, n ObjectName) bool {
	return m.Visible == nil || m.Visible(assoc, n)
}

func (m *EventManager) page() int {
	if m.PageSize > 0 {
		return m.PageSize
	}
	return 50
}

// DefineCondition defines a condition locally (not through the service):
// such conditions are not deletable by clients. A monitored condition
// without a variable starts enabled and idle; its transitions are the
// server's own (Transition).
func (m *EventManager) DefineCondition(d EventConditionDef) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	k := keyOf(d.Name, nil)
	if m.conds[k] != nil {
		return fmt.Errorf("mms: event condition %s exists", d.Name)
	}
	m.conds[k] = m.newCondition(d, nil, false)
	return nil
}

func (m *EventManager) newCondition(d EventConditionDef, owner any, deletable bool) *eventCondition {
	c := &eventCondition{name: d.Name, owner: owner, class: d.Class, priority: d.Priority, severity: d.Severity,
		monitored: d.Monitored, evalInterval: d.EvaluationInterval, deletable: deletable, state: ECStateDisabled}
	if d.AlarmSummaryReports != nil {
		c.alarmSummaryReports = *d.AlarmSummaryReports
	}
	if c.class == ECMonitored {
		// A monitored condition is defined enabled; its state follows the
		// variable, or is idle for a locally detected event.
		c.enabled = true
		c.state = ECStateIdle
		if c.monitored != nil && m.MonitoredValue != nil {
			if v, err := m.MonitoredValue(*c.monitored); err == nil && v {
				c.state = ECStateActive
			}
		}
	}
	return c
}

// HasEnrollment reports whether an association holds a notification
// enrollment on a condition.
func (m *EventManager) HasEnrollment(cond ObjectName, assoc any) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	c := m.conds[keyOf(cond, nil)]
	if c == nil {
		return false
	}
	for _, e := range c.enrollments {
		if e.client == assoc {
			return true
		}
	}
	return false
}

// Enrollments is the number of enrollments on a condition.
func (m *EventManager) Enrollments(cond ObjectName) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	if c := m.conds[keyOf(cond, nil)]; c != nil {
		return len(c.enrollments)
	}
	return 0
}

// pending is a notification to deliver after the lock is released.
type pending struct {
	e      *eventEnrollment
	client any
	n      EventNotification
	action []byte
}

// Transition reports a change of a monitored condition's state detected by
// the server (a locally defined event, arcs 3 and 4 of 21.1.2) and runs the
// Procedure for Event Transition Processing.
func (m *EventManager) Transition(cond ObjectName, state int, at time.Time) error {
	m.mu.Lock()
	m.init()
	c := m.conds[keyOf(cond, nil)]
	if c == nil {
		m.mu.Unlock()
		return fmt.Errorf("mms: no event condition %s", cond)
	}
	if c.class != ECMonitored || !c.enabled {
		m.mu.Unlock()
		return fmt.Errorf("mms: event condition %s is not an enabled monitored condition", cond)
	}
	out := m.transition(c, state, EventTime{Time: at})
	m.mu.Unlock()
	m.deliver(out)
	return nil
}

// Trigger reports a network-triggered event the server detected itself
// (18.1 d).
func (m *EventManager) Trigger(cond ObjectName, at time.Time) error {
	m.mu.Lock()
	m.init()
	c := m.conds[keyOf(cond, nil)]
	if c == nil || c.class != ECNetworkTriggered {
		m.mu.Unlock()
		return fmt.Errorf("mms: no network-triggered event condition %s", cond)
	}
	out := m.trigger(c, EventTime{Time: at})
	m.mu.Unlock()
	m.deliver(out)
	return nil
}

// VariableChanged re-evaluates the enabled monitored conditions that refer
// to a variable (after the server changed its value).
func (m *EventManager) VariableChanged(n ObjectName, at time.Time) {
	if m.MonitoredValue == nil {
		return
	}
	m.mu.Lock()
	m.init()
	var out []pending
	for _, c := range m.sortedConds() {
		if c.class != ECMonitored || !c.enabled || c.monitored == nil || *c.monitored != n {
			continue
		}
		v, err := m.MonitoredValue(n)
		if err != nil {
			continue
		}
		st := ECStateIdle
		if v {
			st = ECStateActive
		}
		out = append(out, m.transition(c, st, EventTime{Time: at})...)
	}
	m.mu.Unlock()
	m.deliver(out)
}

// transitionBit is the Transitions bit of a change of state.
func transitionBit(from, to int) int {
	switch {
	case from == ECStateIdle && to == ECStateDisabled:
		return TransIdleToDisabled
	case from == ECStateActive && to == ECStateDisabled:
		return TransActiveToDisabled
	case from == ECStateDisabled && to == ECStateIdle:
		return TransDisabledToIdle
	case from == ECStateActive && to == ECStateIdle:
		return TransActiveToIdle
	case from == ECStateDisabled && to == ECStateActive:
		return TransDisabledToActive
	}
	return TransIdleToActive
}

// transition is the Procedure for Event Transition Processing of a
// monitored condition (18.1.1): the condition is updated, each enrollment's
// state follows its acknowledgement rule, and each enrollment whose
// transitions include this one is notified (with its action executed).
func (m *EventManager) transition(c *eventCondition, to int, at EventTime) []pending {
	from := c.state
	if from == to {
		return nil
	}
	c.state = to
	switch to {
	case ECStateActive:
		c.toActive = at
	case ECStateIdle:
		c.toIdle = at
	}
	bit := transitionBit(from, to)
	var out []pending
	for _, e := range c.enrollments {
		e.state = nextEEState(e.ackRule, e.state, to)
		if e.transitions.Get(bit) {
			out = append(out, m.notification(c, e, at))
		}
	}
	return out
}

// trigger processes a network-triggered condition: every enrollment on it
// is notified (their transitions are the empty set, 21.1.1.5).
func (m *EventManager) trigger(c *eventCondition, at EventTime) []pending {
	var out []pending
	for _, e := range c.enrollments {
		out = append(out, m.notification(c, e, at))
	}
	return out
}

func (m *EventManager) notification(c *eventCondition, e *eventEnrollment, at EventTime) pending {
	n := EventNotification{Enrollment: e.name, Condition: c.name, Severity: c.severity, State: c.state,
		NotificationLost: e.lost}
	if at.IsSeq {
		s := at.Seq
		n.TimeSeq = &s
	} else {
		n.Time = at.Time
	}
	if c.class == ECMonitored {
		n.AckRule, n.HasAckRule = e.ackRule, true
	}
	p := pending{e: e, client: e.client, n: n}
	if e.action != nil {
		p.action = e.action.service
		p.n.Action = &ActionResult{Action: e.action.name}
	}
	return p
}

// nextEEState is the enrollment's state after its condition changes to
// ecState (Figures 21 to 24 of ISO 9506-1:2003; findings F-693 for the
// ack-all diagram).
func nextEEState(rule, cur, ecState int) int {
	switch ecState {
	case ECStateDisabled:
		return EEDisabled
	case ECStateActive:
		if rule == AckNone {
			return EEActive
		}
		return EEActiveNoAckA
	}
	switch rule {
	case AckNone, AckSimple:
		return EEIdle
	case AckActive:
		if cur == EEActiveNoAckA {
			return EEIdleNoAckA
		}
		return EEIdleAcked
	}
	switch cur { // ack-all
	case EEActiveNoAckA:
		return EEIdleNoAckA
	case EEActiveAcked:
		return EEIdleNoAckI
	}
	return EEIdleAcked
}

// initialEEState is a new enrollment's state for its condition's state.
func initialEEState(rule, ecState int) int {
	switch ecState {
	case ECStateDisabled:
		return EEDisabled
	case ECStateActive:
		if rule == AckNone {
			return EEActive
		}
		return EEActiveAcked
	}
	if rule == AckNone || rule == AckSimple {
		return EEIdle
	}
	return EEIdleAcked
}

// deliver executes the pending actions and sends the notifications.
func (m *EventManager) deliver(out []pending) {
	for i := range out {
		p := &out[i]
		if p.client == nil {
			m.mu.Lock()
			p.e.lost = true
			m.mu.Unlock()
			continue
		}
		if p.action != nil && p.n.Action != nil {
			if m.Exec == nil {
				p.n.Action = nil
			} else if resp, se := m.Exec(p.client, p.action); se != nil {
				p.n.Action.Error = *se
			} else {
				p.n.Action.Success, p.n.Action.Response = true, resp
			}
		}
		var err error
		if m.Send != nil {
			err = m.Send(p.client, p.n)
		}
		m.mu.Lock()
		p.e.lost = err != nil
		m.mu.Unlock()
	}
}

// Release ends an association: its AA-specific conditions, actions and
// enrollments are deleted, and its other enrollments stay without a client
// (their notifications are lost).
func (m *EventManager) Release(assoc any) {
	m.mu.Lock()
	m.init()
	var out []pending
	for k, e := range m.enrolls {
		if k.owner == assoc && k.owner != nil {
			m.removeEnrollment(k, e)
		} else if e.client == assoc {
			e.client = nil
		}
	}
	for k, a := range m.actions {
		if k.owner == assoc && k.owner != nil {
			for _, e := range m.enrolls {
				if e.action == a {
					e.action = nil
				}
			}
			delete(m.actions, k)
		}
	}
	for k, c := range m.conds {
		if k.owner == assoc && k.owner != nil {
			out = append(out, m.removeCondition(k, c)...)
		}
	}
	m.mu.Unlock()
	m.deliver(out)
}

func (m *EventManager) removeEnrollment(k objKey, e *eventEnrollment) {
	delete(m.enrolls, k)
	if e.cond != nil {
		for i, x := range e.cond.enrollments {
			if x == e {
				e.cond.enrollments = append(e.cond.enrollments[:i], e.cond.enrollments[i+1:]...)
				break
			}
		}
	}
	if e.action != nil {
		e.action.refs--
	}
}

// removeCondition deletes a condition: enrollments that asked for
// any-to-deleted are notified without a state (18.1 e, 18.3.1.1.4), and
// every enrollment's condition becomes undefined.
func (m *EventManager) removeCondition(k objKey, c *eventCondition) []pending {
	delete(m.conds, k)
	var out []pending
	for _, e := range c.enrollments {
		if e.transitions.Get(TransAnyToDeleted) {
			p := m.notification(c, e, EventTime{Time: time.Now()})
			p.n.NoState, p.n.Action, p.action = true, nil, nil
			out = append(out, p)
		}
		e.cond = nil
		e.state = EEUndefined
	}
	c.enrollments = nil
	return out
}

func (m *EventManager) sortedConds() []*eventCondition {
	out := make([]*eventCondition, 0, len(m.conds))
	for _, c := range m.conds {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return nameLess(out[i].name, out[j].name) })
	return out
}

func nameLess(a, b ObjectName) bool {
	if a.Scope != b.Scope {
		return a.Scope < b.Scope
	}
	if a.Domain != b.Domain {
		return a.Domain < b.Domain
	}
	return a.Item < b.Item
}

// Outcome is the result of an event service: a response element, a
// service error, or a reject of the request as invalid.
type Outcome struct {
	Response []byte
	Error    *ServiceError
	Reject   bool
	// Deliver, when set, sends the notifications the request caused; the
	// server calls it after sending the response (ISO 9506-1:2003
	// 18.2.2.2: transition processing follows the response).
	Deliver func()
}

func fail(class, code int) Outcome { return Outcome{Error: &ServiceError{Class: class, Code: code}} }

var (
	errUndefined = fail(ClassDefinition, CodeDefObjectUndefined)
	errExists    = fail(ClassDefinition, CodeDefObjectExists)
	errNotHere   = fail(ClassAccess, CodeAccNonExistent)
)

// IsEventService reports whether a confirmed service is one Handle takes.
func IsEventService(svc int) bool {
	return svc >= SvcDefineEventCondition && svc <= SvcGetAlarmEnrollmentSummary
}

// EventServices are the service bits a server offers when it hands these
// services to an EventManager (with the eventNotification bit).
var EventServices = []int{SvcDefineEventCondition, SvcDeleteEventCondition, SvcGetEventConditionAttributes,
	SvcReportEventConditionStatus, SvcAlterEventConditionMonitoring, SvcTriggerEvent, SvcDefineEventAction,
	SvcDeleteEventAction, SvcGetEventActionAttributes, SvcReportEventActionStatus, SvcDefineEventEnrollment,
	SvcDeleteEventEnrollment, SvcAlterEventEnrollment, SvcReportEventEnrollmentStatus, SvcGetEventEnrollmentAttributes,
	SvcAcknowledgeEventNotification, SvcGetAlarmSummary, SvcGetAlarmEnrollmentSummary, BitEventNotification}

// Handle executes an event service request of an association.
func (m *EventManager) Handle(assoc any, req Request) Outcome {
	m.mu.Lock()
	m.init()
	var out []pending
	o := m.handle(assoc, req, &out)
	m.mu.Unlock()
	if len(out) > 0 {
		o.Deliver = func() { m.deliver(out) }
	}
	return o
}

func (m *EventManager) lookupCond(assoc any, n ObjectName) *eventCondition {
	if !m.visible(assoc, n) {
		return nil
	}
	return m.conds[keyOf(n, assoc)]
}

func (m *EventManager) handle(assoc any, req Request, out *[]pending) Outcome {
	body := req.Body
	switch req.Service {
	case SvcDefineEventCondition:
		d, err := DecodeDefineEventCondition(body)
		if err != nil || d.Class < ECNetworkTriggered || d.Class > ECMonitored || d.Priority > 127 || d.Severity > 127 {
			return Outcome{Reject: true}
		}
		if !m.visible(assoc, d.Name) {
			return errNotHere
		}
		if d.Monitored != nil {
			if m.MonitoredValue == nil || d.Class != ECMonitored {
				return fail(ClassDefinition, CodeDefTypeUnsupported)
			}
			if !m.visible(assoc, *d.Monitored) {
				return errUndefined
			}
			if _, err := m.MonitoredValue(*d.Monitored); err != nil {
				return fail(ClassDefinition, CodeDefTypeInconsistent)
			}
		}
		k := keyOf(d.Name, assoc)
		if m.conds[k] != nil {
			return errExists
		}
		m.conds[k] = m.newCondition(d, assoc, true)
		return Outcome{Response: nullResponse(SvcDefineEventCondition)}
	case SvcDeleteEventCondition:
		s, err := DecodeDeleteEventCondition(body)
		if err != nil {
			return Outcome{Reject: true}
		}
		var notDeleted uint32
		for _, c := range m.sortedConds() {
			if !m.inScope(assoc, c.name, c.owner, s) {
				continue
			}
			if !c.deletable || (c.name.Scope == ScopeAA && c.owner != assoc) {
				notDeleted++
				continue
			}
			*out = append(*out, m.removeCondition(keyOf(c.name, c.owner), c)...)
		}
		return Outcome{Response: DeleteEventConditionResponse(notDeleted)}
	case SvcGetEventConditionAttributes:
		n, err := bodyName(body)
		if err != nil {
			return Outcome{Reject: true}
		}
		c := m.lookupCond(assoc, n)
		if c == nil {
			return errUndefined
		}
		a := EventConditionAttrs{Deletable: c.deletable, Class: c.class, Priority: c.priority, Severity: c.severity}
		if c.class == ECMonitored {
			a.AlarmSummaryReports = c.alarmSummaryReports
			a.Monitored, a.MonitoredUndefined = c.monitored, c.monitored == nil
			a.EvaluationInterval = c.evalInterval
		}
		return Outcome{Response: EventConditionAttributesResponse(a)}
	case SvcReportEventConditionStatus:
		n, err := bodyName(body)
		if err != nil {
			return Outcome{Reject: true}
		}
		c := m.lookupCond(assoc, n)
		if c == nil {
			return errUndefined
		}
		st := EventConditionStatus{State: c.state, NumEnrollments: uint32(len(c.enrollments))}
		if c.class == ECMonitored {
			en := c.enabled
			st.Enabled, st.TimeToActive, st.TimeToIdle = &en, c.toActive, c.toIdle
		}
		return Outcome{Response: EventConditionStatusResponse(st)}
	case SvcAlterEventConditionMonitoring:
		mo, err := DecodeAlterEventConditionMonitoring(body)
		if err != nil || (mo.Priority != nil && *mo.Priority > 127) {
			return Outcome{Reject: true}
		}
		c := m.lookupCond(assoc, mo.Name)
		if c == nil {
			return errUndefined
		}
		if c.class != ECMonitored {
			return fail(ClassService, CodeSvcObjectConstraint)
		}
		if mo.Priority != nil {
			c.priority = *mo.Priority
		}
		if mo.AlarmSummaryReports != nil {
			c.alarmSummaryReports = *mo.AlarmSummaryReports
		}
		if mo.EvaluationInterval != nil {
			c.evalInterval = mo.EvaluationInterval
		}
		if mo.Enabled != nil && *mo.Enabled != c.enabled {
			now := EventTime{Time: time.Now()}
			if !*mo.Enabled {
				*out = append(*out, m.transition(c, ECStateDisabled, now)...)
				c.enabled = false
			} else {
				c.enabled = true
				st := ECStateIdle
				if c.monitored != nil && m.MonitoredValue != nil {
					if v, err := m.MonitoredValue(*c.monitored); err == nil && v {
						st = ECStateActive
					}
				}
				*out = append(*out, m.transition(c, st, now)...)
			}
		}
		return Outcome{Response: nullResponse(SvcAlterEventConditionMonitoring)}
	case SvcTriggerEvent:
		n, prio, err := DecodeTriggerEvent(body)
		if err != nil || (prio != nil && *prio > 127) {
			return Outcome{Reject: true}
		}
		c := m.lookupCond(assoc, n)
		if c == nil {
			return errUndefined
		}
		if c.class != ECNetworkTriggered {
			return fail(ClassService, CodeSvcObjectConstraint)
		}
		if prio != nil {
			c.priority = *prio
		}
		*out = append(*out, m.trigger(c, EventTime{Time: time.Now()})...)
		return Outcome{Response: nullResponse(SvcTriggerEvent)}
	case SvcDefineEventAction:
		d, mods, err := DecodeDefineEventAction(body)
		if err != nil {
			return Outcome{Reject: true}
		}
		if mods || m.Exec == nil {
			return fail(ClassDefinition, CodeDefTypeUnsupported)
		}
		if !m.visible(assoc, d.Name) {
			return errNotHere
		}
		k := keyOf(d.Name, assoc)
		if m.actions[k] != nil {
			return errExists
		}
		m.actions[k] = &eventAction{name: d.Name, owner: assoc, service: d.Service, deletable: true}
		return Outcome{Response: nullResponse(SvcDefineEventAction)}
	case SvcDeleteEventAction:
		s, err := DecodeDeleteEventAction(body)
		if err != nil {
			return Outcome{Reject: true}
		}
		var notDeleted uint32
		for k, a := range m.actions {
			if !m.inScope(assoc, a.name, a.owner, s) {
				continue
			}
			if !a.deletable || a.refs > 0 || (a.name.Scope == ScopeAA && a.owner != assoc) {
				notDeleted++
				continue
			}
			delete(m.actions, k)
		}
		return Outcome{Response: DeleteEventActionResponse(notDeleted)}
	case SvcGetEventActionAttributes:
		n, err := bodyName(body)
		if err != nil {
			return Outcome{Reject: true}
		}
		a := m.lookupAction(assoc, n)
		if a == nil {
			return errUndefined
		}
		return Outcome{Response: EventActionAttributesResponse(EventActionAttrs{Deletable: a.deletable, Service: a.service})}
	case SvcReportEventActionStatus:
		n, err := bodyName(body)
		if err != nil {
			return Outcome{Reject: true}
		}
		a := m.lookupAction(assoc, n)
		if a == nil {
			return errUndefined
		}
		return Outcome{Response: unsignedResponse(SvcReportEventActionStatus, uint32(a.refs))}
	case SvcDefineEventEnrollment:
		d, third, err := DecodeDefineEventEnrollment(body)
		if err != nil || d.AckRule < AckNone || d.AckRule > AckAll {
			return Outcome{Reject: true}
		}
		if third {
			return fail(ClassAccess, CodeAccUnsupported)
		}
		if !m.visible(assoc, d.Name) {
			return errNotHere
		}
		c := m.lookupCond(assoc, d.Condition)
		if c == nil {
			return Outcome{Error: ptr(DefineEventEnrollmentError(d.Condition))}
		}
		var a *eventAction
		if d.Action != nil {
			if a = m.lookupAction(assoc, *d.Action); a == nil {
				return Outcome{Error: ptr(DefineEventEnrollmentError(*d.Action))}
			}
		}
		k := keyOf(d.Name, assoc)
		if m.enrolls[k] != nil {
			return errExists
		}
		tr := d.Transitions
		if c.class == ECNetworkTriggered {
			tr = Transitions() // the empty set (21.1.1.5)
		} else if !transitionsFit(d.AckRule, tr) {
			return fail(ClassDefinition, CodeDefAttrInconsistent)
		}
		e := &eventEnrollment{name: d.Name, owner: assoc, client: assoc, cond: c, action: a, hasAction: a != nil,
			transitions: tr, ackRule: d.AckRule, state: initialEEState(d.AckRule, c.state)}
		if d.Name.Scope != ScopeAA {
			e.duration = EEPermanent
		}
		if a != nil {
			a.refs++
		}
		m.enrolls[k] = e
		c.enrollments = append(c.enrollments, e)
		return Outcome{Response: nullResponse(SvcDefineEventEnrollment)}
	case SvcDeleteEventEnrollment:
		d, err := DecodeDeleteEventEnrollment(body)
		if err != nil {
			return Outcome{Reject: true}
		}
		var notDeleted uint32
		for _, k := range m.sortedEnrollKeys() {
			e := m.enrolls[k]
			switch {
			case d.Condition != nil:
				if e.cond == nil || keyOf(e.cond.name, e.cond.owner) != keyOf(*d.Condition, assoc) {
					continue
				}
			case d.Action != nil:
				if e.action == nil || keyOf(e.action.name, e.action.owner) != keyOf(*d.Action, assoc) {
					continue
				}
			default:
				found := false
				for _, n := range d.Specific {
					if keyOf(n, assoc) == k {
						found = true
					}
				}
				if !found {
					continue
				}
			}
			if !m.visible(assoc, e.name) {
				continue
			}
			if e.owner != assoc {
				notDeleted++
				continue
			}
			m.removeEnrollment(k, e)
		}
		return Outcome{Response: DeleteEventEnrollmentResponse(notDeleted)}
	case SvcAlterEventEnrollment:
		ch, err := DecodeAlterEventEnrollment(body)
		if err != nil || (ch.AckRule != nil && (*ch.AckRule < AckNone || *ch.AckRule > AckAll)) {
			return Outcome{Reject: true}
		}
		e := m.lookupEnroll(assoc, ch.Name)
		if e == nil {
			return errUndefined
		}
		rule, tr := e.ackRule, e.transitions
		if ch.AckRule != nil {
			rule = *ch.AckRule
		}
		if ch.Transitions != nil {
			tr = *ch.Transitions
		}
		if e.cond != nil && e.cond.class == ECNetworkTriggered {
			tr = Transitions()
		} else if !transitionsFit(rule, tr) {
			return fail(ClassDefinition, CodeDefAttrInconsistent)
		}
		if rule != e.ackRule && e.cond != nil {
			e.state = initialEEState(rule, e.cond.state)
		}
		e.ackRule, e.transitions = rule, tr
		state, at := EEUndefined, EventTime{}
		if e.cond != nil {
			state = e.state
			at = e.cond.toIdle
			if e.cond.state == ECStateActive {
				at = e.cond.toActive
			}
		}
		return Outcome{Response: AlterEventEnrollmentResponse(state, at)}
	case SvcReportEventEnrollmentStatus:
		n, err := bodyName(body)
		if err != nil {
			return Outcome{Reject: true}
		}
		e := m.lookupEnroll(assoc, n)
		if e == nil {
			return errUndefined
		}
		st := EventEnrollmentStatus{Transitions: e.transitions, NotificationLost: e.lost, Duration: e.duration, State: e.state}
		if e.cond != nil && e.cond.class == ECMonitored {
			r := e.ackRule
			st.AckRule = &r
		}
		return Outcome{Response: EventEnrollmentStatusResponse(st)}
	case SvcGetEventEnrollmentAttributes:
		q, err := DecodeGetEventEnrollmentAttributes(body)
		if err != nil {
			return Outcome{Reject: true}
		}
		var list []EEAttributes
		more := false
		for _, k := range m.sortedEnrollKeys() {
			e := m.enrolls[k]
			if !m.visible(assoc, e.name) || (e.name.Scope == ScopeAA && e.owner != assoc) {
				continue
			}
			switch q.Scope {
			case EEScopeSpecific:
				found := false
				for _, n := range q.Names {
					if keyOf(n, assoc) == k {
						found = true
					}
				}
				if !found {
					continue
				}
			case EEScopeClient:
				if e.client != assoc {
					continue
				}
			case EEScopeCondition:
				if q.Condition == nil || e.cond == nil || keyOf(e.cond.name, e.cond.owner) != keyOf(*q.Condition, assoc) {
					continue
				}
			case EEScopeAction:
				if q.Action == nil || e.action == nil || keyOf(e.action.name, e.action.owner) != keyOf(*q.Action, assoc) {
					continue
				}
			}
			if q.ContinueAfter != nil && !nameLess(*q.ContinueAfter, e.name) {
				continue
			}
			if len(list) == m.page() {
				more = true
				break
			}
			a := EEAttributes{Name: e.name, Deletable: e.owner == assoc, Class: EENotification, Duration: e.duration,
				HasAction: e.hasAction}
			if e.cond != nil {
				n := e.cond.name
				a.Condition = &n
			}
			if e.action != nil {
				n := e.action.name
				a.Action = &n
			}
			list = append(list, a)
		}
		return Outcome{Response: EventEnrollmentAttributesResponse(list, more)}
	case SvcAcknowledgeEventNotification:
		a, err := DecodeAcknowledgeEventNotification(body)
		if err != nil {
			return Outcome{Reject: true}
		}
		e := m.lookupEnroll(assoc, a.Enrollment)
		if e == nil {
			return errUndefined
		}
		acknowledge(e, a, time.Now())
		return Outcome{Response: nullResponse(SvcAcknowledgeEventNotification)}
	case SvcGetAlarmSummary, SvcGetAlarmEnrollmentSummary:
		q, err := DecodeAlarmQuery(body)
		if err != nil {
			return Outcome{Reject: true}
		}
		if req.Service == SvcGetAlarmSummary {
			list, more := m.alarmSummary(assoc, q)
			return Outcome{Response: AlarmSummaryResponse(list, more)}
		}
		list, more := m.alarmEnrollmentSummary(assoc, q)
		return Outcome{Response: AlarmEnrollmentSummaryResponse(list, more)}
	}
	return Outcome{Error: &ServiceError{Class: ClassService, Code: CodeOther}}
}

func ptr[T any](v T) *T { return &v }

// transitionsFit checks an enrollment's transitions against its rule: a
// rule other than none needs the transitions to active, ack-all also those
// to idle (21.1.1.5).
func transitionsFit(rule int, tr BitString) bool {
	if rule == AckNone {
		return true
	}
	if !tr.Get(TransIdleToActive) || !tr.Get(TransDisabledToActive) {
		return false
	}
	return rule != AckAll || (tr.Get(TransActiveToIdle) && tr.Get(TransDisabledToIdle))
}

// acknowledge is the Procedure For Acknowledgement of Event Notifications
// (18.4.2.3) with the acknowledgement arcs 5 and 6 of 21.1.2.
func acknowledge(e *eventEnrollment, a Acknowledgement, now time.Time) {
	c := e.cond
	if c == nil {
		return
	}
	stamp := EventTime{Time: now}
	switch a.State {
	case ECStateActive:
		if !a.Time.Equal(c.toActive) || (e.ackedActive.Defined() && e.ackedActive.Equal(c.toActive)) {
			return // not the last transition to active, or already acknowledged (a)
		}
		switch {
		case c.state == ECStateActive && e.state == EEActiveNoAckA:
			e.state = EEActiveAcked // arc 5
		case c.state == ECStateIdle && e.state == EEIdleNoAckA && e.ackRule == AckActive:
			e.state = EEIdleAcked // arc 6
		case c.state == ECStateIdle && e.state == EEIdleNoAckA && e.ackRule == AckAll:
			e.state = EEIdleNoAckI // arc 6
		case c.state != ECStateActive:
			return
		}
		e.activeAck, e.ackedActive = stamp, c.toActive
	case ECStateIdle:
		if c.state != ECStateIdle || !a.Time.Equal(c.toIdle) || (e.ackedIdle.Defined() && e.ackedIdle.Equal(c.toIdle)) {
			return
		}
		if e.state == EEIdleNoAckI {
			e.state = EEIdleAcked // arc 5
		}
		e.idleAck, e.ackedIdle = stamp, c.toIdle
	}
}

func unacked(e *eventEnrollment) bool {
	return e.state == EEActiveNoAckA || e.state == EEIdleNoAckA || e.state == EEIdleNoAckI
}

// alarmSummary is GetAlarmSummary (18.5.2).
func (m *EventManager) alarmSummary(assoc any, q AlarmQuery) ([]AlarmSummary, bool) {
	var out []AlarmSummary
	for _, c := range m.sortedConds() {
		if !m.alarmCandidate(assoc, c, q) {
			continue
		}
		if q.ContinueAfter != nil && !nameLess(*q.ContinueAfter, c.name) {
			continue
		}
		if len(out) == m.page() {
			return out, true
		}
		un := UnackedNone
		for _, e := range c.enrollments {
			switch e.state {
			case EEActiveNoAckA, EEIdleNoAckA:
				un |= UnackedActive
			case EEIdleNoAckI:
				un |= UnackedIdle
			}
		}
		out = append(out, AlarmSummary{Condition: c.name, Severity: c.severity, State: c.state, Unacked: un,
			TimeToActive: c.toActive, TimeToIdle: c.toIdle})
	}
	return out, false
}

func (m *EventManager) alarmCandidate(assoc any, c *eventCondition, q AlarmQuery) bool {
	if c.class != ECMonitored || !c.alarmSummaryReports || !m.visible(assoc, c.name) ||
		(c.name.Scope == ScopeAA && c.owner != assoc) {
		return false
	}
	if c.severity < q.MostSevere || c.severity > q.LeastSevere {
		return false
	}
	if q.ActiveOnly && c.state != ECStateActive {
		return false
	}
	mine, anyUnacked, allAcked := false, false, true
	for _, e := range c.enrollments {
		if e.client == assoc {
			mine = true
		}
		if unacked(e) {
			anyUnacked, allAcked = true, false
		}
	}
	if q.EnrollmentsOnly && !mine {
		return false
	}
	switch q.AckFilter {
	case AckFilterNotAcked:
		return anyUnacked
	case AckFilterAcked:
		return allAcked
	}
	return true
}

// alarmEnrollmentSummary is GetAlarmEnrollmentSummary (18.6): the
// notification enrollments with an acknowledgement rule other than none
// on the conditions an alarm summary would select.
func (m *EventManager) alarmEnrollmentSummary(assoc any, q AlarmQuery) ([]AlarmEnrollmentSummary, bool) {
	var out []AlarmEnrollmentSummary
	for _, k := range m.sortedEnrollKeys() {
		e := m.enrolls[k]
		c := e.cond
		if c == nil || e.ackRule == AckNone || c.class != ECMonitored || !c.alarmSummaryReports ||
			!m.visible(assoc, e.name) || (e.name.Scope == ScopeAA && e.owner != assoc) {
			continue
		}
		if q.EnrollmentsOnly && e.client != assoc {
			continue
		}
		if c.severity < q.MostSevere || c.severity > q.LeastSevere || (q.ActiveOnly && c.state != ECStateActive) {
			continue
		}
		if (q.AckFilter == AckFilterNotAcked && !unacked(e)) || (q.AckFilter == AckFilterAcked && unacked(e)) {
			continue
		}
		if q.ContinueAfter != nil && !nameLess(*q.ContinueAfter, e.name) {
			continue
		}
		if len(out) == m.page() {
			return out, true
		}
		st := e.state
		out = append(out, AlarmEnrollmentSummary{Enrollment: e.name, Severity: c.severity, State: c.state,
			NotificationLost: e.lost, AckRule: e.ackRule, EEState: &st, TimeToActive: c.toActive,
			TimeActiveAck: e.activeAck, TimeToIdle: c.toIdle, TimeIdleAck: e.idleAck})
	}
	return out, false
}

func (m *EventManager) lookupAction(assoc any, n ObjectName) *eventAction {
	if !m.visible(assoc, n) {
		return nil
	}
	return m.actions[keyOf(n, assoc)]
}

func (m *EventManager) lookupEnroll(assoc any, n ObjectName) *eventEnrollment {
	if !m.visible(assoc, n) {
		return nil
	}
	return m.enrolls[keyOf(n, assoc)]
}

func (m *EventManager) sortedEnrollKeys() []objKey {
	keys := make([]objKey, 0, len(m.enrolls))
	for k := range m.enrolls {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return nameLess(m.enrolls[keys[i]].name, m.enrolls[keys[j]].name) })
	return keys
}

// inScope reports whether an object falls in a delete scope.
func (m *EventManager) inScope(assoc any, n ObjectName, owner any, s DeleteScope) bool {
	if !m.visible(assoc, n) {
		return false
	}
	switch {
	case s.AA:
		return n.Scope == ScopeAA && owner == assoc
	case s.Domain != "":
		return n.Scope == ScopeDomain && n.Domain == s.Domain
	case s.VMD:
		return n.Scope == ScopeVMD
	}
	for _, x := range s.Specific {
		if keyOf(x, assoc) == keyOf(n, owner) {
			return true
		}
	}
	return false
}

// Names lists the names of the event conditions, actions or enrollments
// (class ClassEventCondition, ClassEventAction or ClassEventEnrollment)
// in a scope that an association may see, sorted, for GetNameList.
func (m *EventManager) Names(assoc any, class int, scope Scope, domain string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	var out []string
	add := func(n ObjectName, owner any) {
		if n.Scope != scope || (scope == ScopeDomain && n.Domain != domain) || (scope == ScopeAA && owner != assoc) ||
			!m.visible(assoc, n) {
			return
		}
		out = append(out, n.Item)
	}
	switch class {
	case ClassEventCondition:
		for _, c := range m.conds {
			add(c.name, c.owner)
		}
	case ClassEventAction:
		for _, a := range m.actions {
			add(a.name, a.owner)
		}
	case ClassEventEnrollment:
		for _, e := range m.enrolls {
			add(e.name, e.owner)
		}
	}
	sort.Strings(out)
	return out
}

// ErrNoEventManager is returned by servers without event management.
var ErrNoEventManager = errors.New("mms: event management is not offered")
