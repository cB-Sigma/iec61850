package tase2_test

import (
	"slices"
	"testing"

	"github.com/cB-Sigma/iec61850/mms"
	"github.com/cB-Sigma/iec61850/tase2"
)

// The TASE.2 client proposes the services IEC 60870-6-702:2014 Tables
// A.17 to A.23 require of a client and none it excludes (Status, journals,
// files); the event management services only with event enrollments
// configured (F-879).
// Covers: SIG-IPE-1913
func TestClientCapabilities702(t *testing.T) {
	c := tase2.ClientCapabilities(false)
	for _, b := range []int{mms.SvcGetNameList, mms.SvcIdentify, mms.SvcRead, mms.SvcWrite, mms.SvcGetVariableAccessAttributes,
		mms.SvcDefineNamedVariableList, mms.SvcGetNamedVariableListAttributes, mms.SvcDeleteNamedVariableList,
		mms.BitInformationReport, mms.BitConclude} {
		if !slices.Contains(c.Services, b) {
			t.Errorf("service %d is not proposed", b)
		}
	}
	for _, b := range append([]int{mms.SvcStatus, mms.SvcReadJournal, mms.SvcFileOpen, mms.SvcFileRead, mms.SvcFileDirectory,
		mms.SvcObtainFile, mms.SvcFileDelete, mms.SvcFileClose}, mms.EventServices...) {
		if slices.Contains(c.Services, b) {
			t.Errorf("service %d is proposed", b)
		}
	}
	if e := tase2.ClientCapabilities(true); !slices.Contains(e.Services, mms.SvcDefineEventEnrollment) || !slices.Contains(e.Services, mms.BitEventNotification) {
		t.Error("event services are missing with enrollments")
	}
}
