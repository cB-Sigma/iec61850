package mms

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"testing"
	"time"
)

// Vectors in this file are built by hand from the ASN.1 of ISO 9506-2:2003
// and the types of ISO 9506-1:2003 (clause references at each test).

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// Initiate (ISO 9506-2:2003 8.2; ISO 9506-1:2003 8.1.3.14, 8.1.3.15,
// 8.2.1): every bit of the SIZE(93) services and SIZE(18) parameter bit
// strings is encoded, bit n is the n-th bit from the most significant bit
// of the first octet, and the response negotiates.
// Covers: SIG-IPE-1750
func TestISO9506Initiate(t *testing.T) {
	c := Capabilities{MaxPDU: 65000, MaxOutstanding: 5, Nesting: 10,
		Parameters: []int{CBBStr1, CBBStr2, CBBVnam, CBBValt, CBBVlis},
		Services:   []int{SvcGetNameList, SvcRead, SvcWrite, SvcGetVariableAccessAttributes, SvcGetNamedVariableListAttributes, BitInformationReport, BitConclude}}
	want := "a828" + "800300fde8" + "810105" + "820105" + "83010a" + "a418" + "800101" + "810406f10000" +
		"820d" + "034e08" + "00000000000000" + "0110" + "00"
	if g := hexOf(c.Request().Encode(TagInitiateRequest)); g != want {
		t.Errorf("initiate request = %s\n want %s", g, want)
	}
	// Event services sit at their ConfirmedServiceRequest tags: 57 is
	// octet 7, bit 1 (0x40); eventNotification 80 is octet 10, bit 0.
	ev := Capabilities{MaxOutstanding: 1, Services: []int{SvcDefineEventEnrollment, BitEventNotification}}.Request()
	svc := ev.Services.Contents()
	if svc[0] != 3 || svc[1+7] != 0x40 || svc[1+10] != 0x80 || len(svc) != 13 {
		t.Errorf("event service bits = %x", svc)
	}
	// An IEC 61850-8-1 style request: 11 parameter bits, 85 service bits,
	// version 1; extra or missing bits are tolerated.
	req := Initiate{MaxServOutstandingCalling: 20, MaxServOutstandingCalled: 3, NestingLevel: 4, Version: 2,
		ParameterCBB: bits(11, []int{CBBStr1, CBBStr2, CBBVnam, CBBValt, CBBVlis, CBBCei}), Services: bits(85, []int{1, 4})}
	got, err := DecodeInitiate(mustParse(t, req.Encode(TagInitiateRequest)))
	if err != nil || got.Version != 2 || got.NestingLevel != 4 || !got.ParameterCBB.Get(CBBVlis) || !got.Services.Get(4) {
		t.Fatalf("decode = %+v %v", got, err)
	}
	server := Capabilities{MaxPDU: 32000, MaxOutstanding: 5, Nesting: 10, Parameters: []int{CBBStr1, CBBStr2, CBBVnam, CBBVlis, CBBTpy},
		Services: []int{SvcRead}}
	r, err := server.Respond(got)
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != 1 || r.MaxServOutstandingCalling != 5 || r.MaxServOutstandingCalled != 3 || r.NestingLevel != 4 {
		t.Errorf("negotiated = %+v", r)
	}
	for bit, on := range map[int]bool{CBBStr1: true, CBBStr2: true, CBBVnam: true, CBBVlis: true, CBBValt: false, CBBTpy: false, CBBCei: false} {
		if r.ParameterCBB.Get(bit) != on {
			t.Errorf("negotiated CBB %d = %v", bit, !on)
		}
	}
	if r.ParameterCBB.NBits != NumParameterBits || r.Services.NBits != NumServiceBits {
		t.Errorf("response sizes %d, %d", r.ParameterCBB.NBits, r.Services.NBits)
	}
	resp, ok := InitiateResponseTo(req.Encode(TagInitiateRequest), server)
	if !ok || resp[0] != TagInitiateResponse {
		t.Errorf("response = %x", resp)
	}
	if bad, ok := InitiateResponseTo(unhex(t, "a803800101"), server); ok || hexOf(bad) != "aa05a003880100" {
		t.Errorf("initiate error = %x %v", bad, ok)
	}
	if _, err := server.Respond(Initiate{Version: 0, MaxServOutstandingCalling: 1, MaxServOutstandingCalled: 1}); err == nil {
		t.Error("version 0 accepted")
	}
}

// A confirmed request is invokeID, an optional listOfModifiers, the
// service and an optional service-ext [79] (ISO 9506-2:2003 7.1); a
// RejectPDU names the PDU type and reason (8.6); ServiceError carries the
// class, code, additional code, description and service-specific
// information (7.4.1).
// Covers: SIG-IPE-1751
func TestISO9506RequestRejectAndError(t *testing.T) {
	plain := ConfirmedRequest(9, ReadRequest(VariableSpec{Vars: []ObjectName{VMDName("X")}}))
	r, err := DecodeConfirmedRequest(mustParse(t, plain))
	if err != nil || r.Service != SvcRead || r.InvokeID != 9 || r.Modifiers {
		t.Fatalf("plain = %+v %v", r, err)
	}
	withMods := T(TagConfirmedRequest, Uint(0x02, 3), T(0x30, T(0xa0)), IdentifyRequest(), TH(0xa0, 79, T(0x05)))
	r, err = DecodeConfirmedRequest(mustParse(t, withMods))
	if err != nil || r.Service != SvcIdentify || !r.Modifiers {
		t.Fatalf("with modifiers and service-ext = %+v %v", r, err)
	}
	for _, tc := range []struct {
		got  []byte
		want string
	}{
		{RejectPDU(5), "a406800105810101"},
		{RejectInvalidArgumentPDU(5), "a406800105810104"},
		{RejectPDUFor(0, RejectPDUError, RejectPDUUnknownType), "a403850100"},
		{ConfirmedErrorPDUFor(1, DefineEventEnrollmentError(DomainName("D", "X"))), "a216800101a211a003820101a30aa808a1061a01441a0158"},
	} {
		if g := hexOf(tc.got); g != tc.want {
			t.Errorf("encoded %s, want %s", g, tc.want)
		}
	}
	id, ok, rej := DecodeReject(mustParse(t, RejectInvalidArgumentPDU(5)))
	if !ok || id != 5 || rej.PDU != RejectConfirmedRequest || rej.Code != RejectInvalidArgument {
		t.Errorf("reject = %d %v %+v", id, ok, rej)
	}
	if _, ok, rej := DecodeReject(mustParse(t, RejectPDUFor(0, RejectPDUError, RejectPDUInvalid))); ok || rej.PDU != RejectPDUError || rej.Code != 1 {
		t.Errorf("pdu-error reject = %v %+v", ok, rej)
	}
	add := int64(-3)
	se := ServiceError{Class: ClassAccess, Code: CodeAccDenied, AdditionalCode: &add, Description: "not in the bilateral table"}
	var got *ServiceError
	if err := decodeServiceError(mustParse(t, ConfirmedErrorPDUFor(2, se))); !errors.As(err, &got) ||
		got.Class != ClassAccess || got.Code != CodeAccDenied || *got.AdditionalCode != -3 || got.Description != se.Description {
		t.Errorf("service error = %+v", got)
	}
	full, err := DecodeServiceError(bytes.Join(DefineEventEnrollmentError(VMDName("C")).contents(), nil))
	if err != nil || full.Class != ClassDefinition || hexOf(full.Specific) != "a803800143" {
		t.Errorf("specific info = %+v %v", full, err)
	}
}

// Data (ISO 9506-2:2003 14.4.2): bcd [13], booleanArray [14] (read as an
// array of booleans), objId [15]; FloatingPoint of any exponent width
// (14.4.2.2); TypeDescription (ISO 9506-1:2003 14.2.1): generalized-time
// and objId are NULL, bcd Unsigned8, mMSString read in both tag forms.
// Covers: SIG-IPE-1752
func TestISO9506DataAlternatives(t *testing.T) {
	d, err := DecodeData(mustParse(t, unhex(t, "8d0152")))
	if err != nil || d.Kind != KBCD || d.Uint != 82 {
		t.Errorf("bcd = %+v %v", d, err)
	}
	d, err = DecodeData(mustParse(t, unhex(t, "8e0205a8")))
	if err != nil || d.Kind != KArray || len(d.Elems) != 3 || !d.Elems[0].Bool || d.Elems[1].Bool || !d.Elems[2].Bool {
		t.Errorf("boolean array = %+v %v", d, err)
	}
	d, err = DecodeData(mustParse(t, T(0x8f, OID("1.0.9506.2.1"))))
	if err != nil || d.Str != "1.0.9506.2.1" || hexOf(d.Encode()) != "8f0528ca220201" {
		t.Errorf("objId = %+v %v %x", d, err, d.Encode())
	}
	for _, tc := range []struct {
		in     string
		want   float64
		double bool
	}{
		{"8705083fc00000", 1.5, false},
		{"87090bc000000000000000", -2, true},
		{"8703053e00", 1.5, false}, // exponent width 5, 10 fraction bits
		{"870305c000", -2, false},  // -2
		{"8703050001", math.Ldexp(1, -24), false},
		{"8704083f8000", 1, false}, // exponent width 8 in 3 octets
	} {
		d, err := DecodeData(mustParse(t, unhex(t, tc.in)))
		if err != nil || d.Float != tc.want || d.Double != tc.double {
			t.Errorf("%s = %v (double %v) %v, want %v", tc.in, d.Float, d.Double, err, tc.want)
		}
	}
	if d, _ := DecodeData(mustParse(t, unhex(t, "8703057c00"))); !math.IsInf(d.Float, 1) {
		t.Errorf("infinity = %v", d.Float)
	}
	if d, _ := DecodeData(mustParse(t, unhex(t, "870305fe00"))); !math.IsNaN(d.Float) {
		t.Errorf("NaN = %v", d.Float)
	}
	if _, err := DecodeData(mustParse(t, unhex(t, "870100"))); err == nil {
		t.Error("a one-octet floating point was accepted")
	}
	for _, tc := range []struct {
		t    TypeSpec
		want string
	}{
		{TypeSpec{Kind: KGenTime}, "8b00"},
		{TypeSpec{Kind: KObjID}, "8f00"},
		{TypeSpec{Kind: KBCD, Size: 4}, "8d0104"},
		{TypeSpec{Kind: KMMSString, Size: -255}, "9002ff01"},
		{TypeSpec{Kind: KBinaryTime, Size: 6}, "8c01ff"},
	} {
		if g := hexOf(tc.t.Encode()); g != tc.want {
			t.Errorf("type %s = %s, want %s", tc.t.Kind, g, tc.want)
		}
		back, err := DecodeTypeSpec(mustParse(t, tc.t.Encode()))
		if err != nil || back.Kind != tc.t.Kind || back.Size != tc.t.Size {
			t.Errorf("type %s round trip = %+v %v", tc.t.Kind, back, err)
		}
	}
	if ts, err := DecodeTypeSpec(mustParse(t, unhex(t, "b003020114"))); err != nil || ts.Kind != KMMSString || ts.Size != 20 {
		t.Errorf("explicit mMSString = %+v %v", ts, err)
	}
}

// Alternate access (ISO 9506-2:2003 14.3.1, 14.5.1): selectAccess
// component [1], index [2], indexRange [3], allElements [4];
// selectAlternateAccess [0]; named [5]; carried as alternateAccess [5] of
// a listOfVariable element; applied to a value by its type. Read with
// specificationWithResult returns the specification (14.6).
// Covers: SIG-IPE-1753
func TestISO9506AlternateAccess(t *testing.T) {
	spec := VariableSpec{Vars: []ObjectName{VMDName("X"), VMDName("Y")},
		Alt: []AlternateAccess{{{Kind: AltComponent, Component: "mag"}}, nil}}
	if g := hexOf(spec.Encode()); g != "a015300ca003800158a50581036d6167"+"3005a003800159" {
		t.Errorf("component access = %s", g)
	}
	nested := AlternateAccess{{Kind: AltComponent, Component: "mag", Nested: AlternateAccess{{Kind: AltIndex, Index: 2}}}}
	if g := hexOf(T(0xa5, nested.elements()...)); g != "a50ca00a80036d6167300382010"+"2" {
		t.Errorf("nested access = %s", g)
	}
	named := AlternateAccess{{Name: "a", Kind: AltAll}, {Name: "b", Kind: AltIndexRange, Index: 1, Count: 2}}
	if g := hexOf(T(0xa5, named.elements()...)); g != "a514a5058001618400a50b800162a306800101810102" {
		t.Errorf("named access = %s", g)
	}
	for _, a := range []AlternateAccess{nested, named} {
		back, err := DecodeAlternateAccess(T(0x30, a.elements()...)[2:])
		if err != nil || hexOf(T(0x30, back.elements()...)) != hexOf(T(0x30, a.elements()...)) {
			t.Errorf("round trip %+v %v", back, err)
		}
	}
	dec, err := DecodeVariableSpec(mustParse(t, spec.Encode()))
	if err != nil || len(dec.Alt) != 2 || dec.AltOf(0)[0].Component != "mag" || dec.AltOf(1) != nil {
		t.Errorf("decoded spec = %+v %v", dec, err)
	}
	typ := TypeSpec{Kind: KStructure, Components: []Component{
		{Name: "stVal", Type: TypeSpec{Kind: KBool}},
		{Name: "mag", Type: TypeSpec{Kind: KArray, Elements: 3, Elem: &TypeSpec{Kind: KInt, Size: 32}}},
	}}
	val := Structure(Boolean(true), Array(Integer(10), Integer(20), Integer(30)))
	v, vt, err := ApplyAlternateAccess(val, typ, nested)
	if err != nil || v.Int != 30 || vt.Kind != KInt {
		t.Errorf("nested apply = %+v %+v %v", v, vt, err)
	}
	v, vt, err = ApplyAlternateAccess(val, typ, AlternateAccess{{Name: "s", Kind: AltComponent, Component: "stVal"},
		{Name: "r", Kind: AltComponent, Component: "mag", Nested: AlternateAccess{{Kind: AltIndexRange, Index: 1, Count: 2}}}})
	if err != nil || v.Kind != KStructure || !v.Elems[0].Bool || len(v.Elems[1].Elems) != 2 || v.Elems[1].Elems[0].Int != 20 ||
		vt.Components[1].Name != "r" || vt.Components[1].Type.Elements != 2 {
		t.Errorf("named apply = %+v %+v %v", v, vt, err)
	}
	if _, _, err := ApplyAlternateAccess(val, typ, AlternateAccess{{Kind: AltComponent, Component: "nope"}}); err != ErrObjectNonExistent {
		t.Errorf("missing component = %v", err)
	}
	if _, _, err := ApplyAlternateAccess(val, typ, AlternateAccess{{Kind: AltIndex, Index: 0}}); err != ErrTypeInconsistent {
		t.Errorf("index of a structure = %v", err)
	}
	req := ReadRequestWithSpec(VariableSpec{Vars: []ObjectName{VMDName("X")}})
	s2, with, err := ReadArgsWithSpec(mustParse(t, req))
	if err != nil || !with || s2.Vars[0] != VMDName("X") || hexOf(req[:4]) != "a40e8001" {
		t.Errorf("read with spec = %+v %v %v %x", s2, with, err, req)
	}
	resp := ReadResponseWithSpec(&s2, []AccessResult{{Data: Integer(1)}})
	f, _ := fields(mustParse(t, resp))
	if _, ok := f[0]; !ok {
		t.Errorf("response without the specification: %x", resp)
	}
	res, err := decodeReadResponse(mustParse(t, resp))
	if err != nil || res[0].Data.Int != 1 {
		t.Errorf("results = %+v %v", res, err)
	}
}

// Identify (ISO 9506-2:2003 10.6) and Status (10.3, 10.2).
// Covers: SIG-IPE-1754
func TestISO9506IdentifyAndStatus(t *testing.T) {
	if g := hexOf(IdentifyRequest()); g != "8200" {
		t.Errorf("identify request = %s", g)
	}
	if g := hexOf(StatusRequest(false)); g != "800100" {
		t.Errorf("status request = %s", g)
	}
	id := Identity{Vendor: "V", Model: "M", Revision: "1", AbstractSyntaxes: []string{"1.0.9506.2.1"}}
	resp := IdentifyResponse(id)
	if g := hexOf(resp); g != "a21280015681014d820131a307060528ca220201" {
		t.Errorf("identify response = %s", g)
	}
	back, err := DecodeIdentity(mustParse(t, resp))
	if err != nil || back.Vendor != "V" || back.AbstractSyntaxes[0] != "1.0.9506.2.1" {
		t.Errorf("identity = %+v %v", back, err)
	}
	st := StatusResponse(VMDStatus{Logical: LogicalStateChangesAllowed, Physical: PhysicalOperational})
	if g := hexOf(st); g != "a006800100810100" {
		t.Errorf("status response = %s", g)
	}
	if s, err := DecodeStatus(mustParse(t, st)); err != nil || s.Logical != 0 || s.Physical != 0 {
		t.Errorf("status = %+v %v", s, err)
	}
}

// EventNotification (ISO 9506-2:2003 18.3; findings F-528 settled): the
// full layout with a time sequence identifier, the acknowledgement rule
// [7], notificationLost [6] and an action result [8].
// Covers: SIG-IPE-1755
func TestISO9506EventNotificationLayout(t *testing.T) {
	seq := uint32(7)
	n := EventNotification{Enrollment: ObjectName{Scope: ScopeAA, Item: "E1"}, Condition: VMDName("C"), Severity: 64,
		State: ECStateActive, TimeSeq: &seq, AckRule: AckSimple, HasAckRule: true}
	want := "a31ba219a0048202453" + "1a103800143820140830102a403810107870101"
	if g := hexOf(EventNotificationPDU(n)); g != want {
		t.Errorf("notification = %s\n want %s", g, want)
	}
	n.NotificationLost, n.NoState = true, true
	n.Action = &ActionResult{Action: VMDName("A"), Success: true, Response: ReadResponse([]AccessResult{{Data: Boolean(true)}})}
	got, err := DecodeEventNotification(mustParse(t, EventNotificationPDU(n)))
	if err != nil || !got.NoState || !got.NotificationLost || got.AckRule != AckSimple || got.TimeSeq == nil || *got.TimeSeq != 7 ||
		got.Action == nil || !got.Action.Success || got.Action.Action != VMDName("A") || hexOf(got.Action.Response) != hexOf(n.Action.Response) {
		t.Errorf("round trip = %+v %v", got, err)
	}
	pos := uint32(1)
	n.Action = &ActionResult{Action: VMDName("A"), ModifierPosition: &pos, Error: ServiceError{Class: ClassAccess, Code: CodeAccDenied}}
	got, err = DecodeEventNotification(mustParse(t, EventNotificationPDU(n)))
	if err != nil || got.Action.Success || *got.Action.ModifierPosition != 1 || got.Action.Error.Code != CodeAccDenied {
		t.Errorf("failure round trip = %+v %v", got.Action, err)
	}
	// The transition time is mandatory.
	if _, err := DecodeEventNotification(mustParse(t, T(TagUnconfirmed, T(0xa2, T(0xa0, VMDName("E").Encode()),
		T(0xa1, VMDName("C").Encode()), Uint(0x82, 1))))); err == nil {
		t.Error("a notification without a transition time was accepted")
	}
}

// Event condition, action and enrollment service PDUs (ISO 9506-2:2003
// 19.2 to 19.6, 20.2 to 20.5, 21.2 to 21.6): tags, explicit tagging of the
// ObjectName and CHOICE requests, the differing delete scope tags, and
// round trips.
// Covers: SIG-IPE-1756
func TestISO9506EventServicePDUs(t *testing.T) {
	ee, ec := ObjectName{Scope: ScopeAA, Item: "E1"}, VMDName("C")
	for _, tc := range []struct {
		got  []byte
		want string
	}{
		{DefineEventEnrollmentRequest(EventEnrollmentDef{Name: ee, Condition: ec, Transitions: Transitions(TransIdleToActive), AckRule: AckSimple}),
			"bf3912a0048202453" + "1a10380014382020104830101"},
		{TriggerEventRequest(ec, nil), "bf3405a003800143"},
		{GetEventConditionAttributesRequest(ec), "bf3103800143"},
		{ReportEventConditionStatusRequest(ec), "bf3203800143"},
		{DeleteEventConditionRequest(DeleteScope{VMD: true}), "bf30028300"},
		{DeleteEventConditionRequest(DeleteScope{Domain: "D"}), "bf3003820144"},
		{DeleteEventConditionRequest(DeleteScope{AA: true}), "bf30028100"},
		{DeleteEventActionRequest(DeleteScope{Domain: "D"}), "bf3603830144"},
		{DeleteEventActionRequest(DeleteScope{VMD: true}), "bf36028400"},
		{DeleteEventEnrollmentRequest(EnrollmentDeletion{Condition: &ec}), "bf3a05a103800143"},
		{DeleteEventEnrollmentRequest(EnrollmentDeletion{Specific: []ObjectName{ee}}), "bf3a06a00482024531"},
		{nullResponse(SvcDefineEventEnrollment), "9f3900"},
		{DeleteEventConditionResponse(0), "9f300100"},
		{AcknowledgeEventNotificationRequest(Acknowledgement{Enrollment: ee, State: ECStateActive, Time: EventTime{Seq: 7, IsSeq: true}}),
			"bf3e0ea00482024531820102a303810107"},
		{GetAlarmSummaryRequest(DefaultAlarmQuery), "bf3f00"},
		{GetAlarmEnrollmentSummaryRequest(AlarmQuery{AckFilter: AckFilterAll, LeastSevere: 64}), "bf4011800100810100820102a306800100810140"},
		{GetEventEnrollmentAttributesRequest(EnrollmentQuery{Scope: EEScopeClient}), "bf3d00"},
		{AlterEventEnrollmentResponse(EEActiveNoAckA, EventTime{Seq: 3, IsSeq: true}), "bf3b0aa003800103a103810103"},
	} {
		if g := hexOf(tc.got); g != tc.want {
			t.Errorf("encoded %s\n want    %s", g, tc.want)
		}
	}
	yes, iv := true, uint32(500)
	def := EventConditionDef{Name: DomainName("D", "C"), Class: ECMonitored, Priority: 10, Severity: NormalSeverity,
		AlarmSummaryReports: &yes, Monitored: &ObjectName{Scope: ScopeDomain, Domain: "D", Item: "V"}, EvaluationInterval: &iv}
	back, err := DecodeDefineEventCondition(mustParse(t, DefineEventConditionRequest(def)))
	if err != nil || back.Name != def.Name || back.Priority != 10 || back.Severity != 64 || !*back.AlarmSummaryReports ||
		*back.Monitored != *def.Monitored || *back.EvaluationInterval != 500 {
		t.Errorf("define condition = %+v %v", back, err)
	}
	attrs := EventConditionAttrs{Deletable: true, Class: ECMonitored, Priority: 64, Severity: 3, AlarmSummaryReports: true, Monitored: def.Monitored}
	ga, err := decodeEventConditionAttrs(mustParse(t, EventConditionAttributesResponse(attrs)))
	if err != nil || !ga.Deletable || ga.Severity != 3 || *ga.Monitored != *def.Monitored {
		t.Errorf("condition attributes = %+v %v", ga, err)
	}
	st := EventConditionStatus{State: ECStateActive, NumEnrollments: 2, Enabled: &yes, TimeToActive: EventTime{Seq: 9, IsSeq: true}}
	gs, err := decodeEventConditionStatus(mustParse(t, EventConditionStatusResponse(st)))
	if err != nil || gs.State != 2 || gs.NumEnrollments != 2 || !gs.TimeToActive.IsSeq || gs.TimeToIdle.Defined() {
		t.Errorf("condition status = %+v %v", gs, err)
	}
	prio := 5
	mo, err := DecodeAlterEventConditionMonitoring(mustParse(t, AlterEventConditionMonitoringRequest(ConditionMonitoring{Name: ec, Priority: &prio, EvaluationInterval: &iv})))
	if err != nil || *mo.Priority != 5 || *mo.EvaluationInterval != 500 || mo.Enabled != nil {
		t.Errorf("alter monitoring = %+v %v", mo, err)
	}
	if _, err := DecodeAlterEventConditionMonitoring(mustParse(t, AlterEventConditionMonitoringRequest(ConditionMonitoring{Name: ec}))); err == nil {
		t.Error("an alter monitoring request that changes nothing was accepted")
	}
	act := EventActionDef{Name: VMDName("A"), Service: ReadRequest(VariableSpec{Vars: []ObjectName{VMDName("X")}})}
	da, mods, err := DecodeDefineEventAction(mustParse(t, DefineEventActionRequest(act)))
	if err != nil || mods || da.Name != act.Name || !bytes.Equal(da.Service, act.Service) {
		t.Errorf("define action = %+v %v %v", da, mods, err)
	}
	aa, err := decodeEventActionAttrs(mustParse(t, EventActionAttributesResponse(EventActionAttrs{Deletable: true, Service: act.Service})))
	if err != nil || !aa.Deletable || !bytes.Equal(aa.Service, act.Service) {
		t.Errorf("action attributes = %+v %v", aa, err)
	}
	a := VMDName("A")
	de, third, err := DecodeDefineEventEnrollment(mustParse(t, DefineEventEnrollmentRequest(EventEnrollmentDef{Name: ee, Condition: ec,
		Transitions: Transitions(TransIdleToActive, TransAnyToDeleted), AckRule: AckAll, Action: &a})))
	if err != nil || third || de.AckRule != AckAll || !de.Transitions.Get(TransAnyToDeleted) || *de.Action != a {
		t.Errorf("define enrollment = %+v %v %v", de, third, err)
	}
	tr := Transitions(TransActiveToIdle)
	rule := AckAll
	ch, err := DecodeAlterEventEnrollment(mustParse(t, AlterEventEnrollmentRequest(EnrollmentChange{Name: ee, Transitions: &tr, AckRule: &rule})))
	if err != nil || !ch.Transitions.Get(TransActiveToIdle) || *ch.AckRule != AckAll {
		t.Errorf("alter enrollment = %+v %v", ch, err)
	}
	es, err := decodeEventEnrollmentStatus(mustParse(t, EventEnrollmentStatusResponse(EventEnrollmentStatus{Transitions: tr, Duration: EEPermanent, AckRule: &rule, State: EEIdleNoAckI})))
	if err != nil || es.State != EEIdleNoAckI || *es.AckRule != AckAll || es.Duration != EEPermanent {
		t.Errorf("enrollment status = %+v %v", es, err)
	}
	list := []EEAttributes{{Name: ee, Condition: &ec, HasAction: true, Deletable: true, Class: EENotification, Duration: EEPermanent},
		{Name: VMDName("E2"), Class: EENotification}}
	gl, more, err := decodeEEList(mustParse(t, EventEnrollmentAttributesResponse(list, true)))
	if err != nil || !more || len(gl) != 2 || *gl[0].Condition != ec || !gl[0].HasAction || gl[0].Action != nil || gl[1].Condition != nil {
		t.Errorf("enrollment attributes = %+v %v %v", gl, more, err)
	}
	q, err := DecodeGetEventEnrollmentAttributes(mustParse(t, GetEventEnrollmentAttributesRequest(EnrollmentQuery{Scope: EEScopeCondition, Condition: &ec, ContinueAfter: &ee})))
	if err != nil || q.Scope != EEScopeCondition || *q.Condition != ec || *q.ContinueAfter != ee {
		t.Errorf("enrollment query = %+v %v", q, err)
	}
	ack, err := DecodeAcknowledgeEventNotification(mustParse(t, AcknowledgeEventNotificationRequest(Acknowledgement{Enrollment: ee, State: ECStateIdle,
		Time: EventTime{Time: time.Date(2026, 9, 24, 1, 2, 3, 4e6, time.UTC)}})))
	if err != nil || ack.State != ECStateIdle || ack.Time.Time.Second() != 3 {
		t.Errorf("acknowledgement = %+v %v", ack, err)
	}
	aq, err := DecodeAlarmQuery(mustParse(t, GetAlarmSummaryRequest(AlarmQuery{EnrollmentsOnly: true, ActiveOnly: true, AckFilter: AckFilterAcked, MostSevere: 1, LeastSevere: 9, ContinueAfter: &ec})))
	if err != nil || !aq.EnrollmentsOnly || !aq.ActiveOnly || aq.AckFilter != AckFilterAcked || aq.MostSevere != 1 || aq.LeastSevere != 9 || *aq.ContinueAfter != ec {
		t.Errorf("alarm query = %+v %v", aq, err)
	}
	sums, more, err := decodeAlarmSummaries(mustParse(t, AlarmSummaryResponse([]AlarmSummary{{Condition: ec, Severity: 5, State: 2, Unacked: UnackedBoth,
		TimeToActive: EventTime{Seq: 1, IsSeq: true}}}, false)))
	if err != nil || more || sums[0].Unacked != UnackedBoth || sums[0].TimeToActive.Seq != 1 {
		t.Errorf("alarm summary = %+v %v", sums, err)
	}
	eeState := EEActiveAcked
	aes, _, err := decodeAlarmEnrollmentSummaries(mustParse(t, AlarmEnrollmentSummaryResponse([]AlarmEnrollmentSummary{{Enrollment: ee, Severity: 5,
		State: 2, AckRule: AckActive, EEState: &eeState, TimeActiveAck: EventTime{Seq: 4, IsSeq: true}}}, false)))
	if err != nil || aes[0].AckRule != AckActive || *aes[0].EEState != EEActiveAcked || aes[0].TimeActiveAck.Seq != 4 || aes[0].TimeToActive.Defined() {
		t.Errorf("alarm enrollment summary = %+v %v", aes, err)
	}
}
