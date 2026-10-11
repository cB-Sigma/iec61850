package mms

import (
	"testing"
	"time"
)

// The unconfirmed EventNotification (ISO 9506-2 unconfirmed service [2]):
// enrollment and condition names, severity, current state, transition
// time as TimeOfDay, round trip through BER, and ordinary information
// reports are not taken for it.
// Covers: SIG-IPE-1546
func TestEventNotificationRoundTrip(t *testing.T) {
	at := time.Date(2026, 9, 24, 10, 15, 30, 250e6, time.UTC)
	n := EventNotification{Enrollment: DomainName("ICC_A", "Data_failure"), Condition: DomainName("ICC_A", "Data_failure"),
		Severity: 64, State: ECStateActive, Time: at}
	pdu := EventNotificationPDU(n)
	if pdu[0] != TagUnconfirmed {
		t.Fatalf("tag %#x", pdu[0])
	}
	e, _, err := Parse(pdu)
	if err != nil {
		t.Fatal(err)
	}
	kids, _ := e.Children()
	if len(kids) != 1 || kids[0].Tag != 0xa2 {
		t.Fatalf("service tag %#x", kids[0].Tag)
	}
	got, err := DecodeEventNotification(e)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enrollment != n.Enrollment || got.Condition != n.Condition || got.Severity != 64 || got.State != ECStateActive || !got.Time.Equal(at) {
		t.Errorf("round trip = %+v", got)
	}
	vmd := EventNotification{Enrollment: VMDName("E"), Condition: VMDName("BRK1_time"), Severity: 127, State: ECStateIdle, Time: at}
	got, err = DecodeEventNotification(mustParse(t, EventNotificationPDU(vmd)))
	if err != nil || got.Condition != VMDName("BRK1_time") || got.State != ECStateIdle || got.Severity != 127 {
		t.Errorf("VMD round trip = %+v %v", got, err)
	}
	if _, err := DecodeEventNotification(mustParse(t, InformationReportPDU(VariableSpec{Vars: []ObjectName{VMDName("X")}},
		[]AccessResult{{Data: Integer(1)}}))); err == nil {
		t.Error("an information report decoded as an event notification")
	}
	if _, err := DecodeInformationReport(e); err == nil {
		t.Error("an event notification decoded as an information report")
	}
}

func mustParse(t *testing.T, b []byte) Elem {
	t.Helper()
	e, _, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
