package mms_test

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

// The client keeps to the negotiated MaxServOutstandingCalled (ISO
// 9506-1:2003 8.2.1.2.3), reads the server's services supported
// (Supports), and routes unconfirmed PDUs by their service tag: an
// information report [0] to OnReport, an event notification [2] to OnEvent
// (ISO 9506-2:2003 7.2.1).
// Covers: SIG-IPE-1763
func TestMMSClientNegotiatedLimits(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	caps := mms.Capabilities{MaxPDU: 65000, MaxOutstanding: 1, Nesting: 5, Parameters: []int{mms.CBBVnam},
		Services: []int{mms.SvcRead, mms.BitInformationReport, mms.BitEventNotification}}
	var inFlight, most atomic.Int32
	go func() {
		nc, err := l.Accept()
		if err != nil {
			return
		}
		sc, err := mms.AcceptAssociation(nc, func(a mms.Association) (int, int, []byte) {
			resp, _ := mms.InitiateResponseTo(a.Initiate, caps)
			return mms.ACSEAccepted, 0, resp
		})
		if err != nil {
			return
		}
		defer sc.Close()
		n := mms.EventNotification{Enrollment: mms.VMDName("E"), Condition: mms.VMDName("C"), Severity: 1, State: mms.ECStateActive, Time: time.Now()}
		_ = sc.Send(mms.EventNotificationPDU(n))
		_ = sc.Send(mms.InformationReportPDU(mms.VariableSpec{Vars: []mms.ObjectName{mms.VMDName("X")}}, []mms.AccessResult{{Data: mms.Integer(1)}}))
		var mu sync.Mutex
		for {
			pdu, err := sc.Receive()
			if err != nil {
				return
			}
			e, _, _ := mms.Parse(pdu)
			req, err := mms.DecodeConfirmedRequest(e)
			if err != nil {
				continue
			}
			if v := inFlight.Add(1); v > most.Load() {
				most.Store(v)
			}
			go func() {
				time.Sleep(30 * time.Millisecond)
				inFlight.Add(-1)
				mu.Lock()
				defer mu.Unlock()
				_ = sc.Send(mms.ConfirmedResponse(req.InvokeID, mms.ReadResponse([]mms.AccessResult{{Data: mms.Integer(2)}})))
			}()
		}
	}()
	reports := make(chan mms.InformationReport, 4)
	events := make(chan mms.EventNotification, 4)
	c, err := mms.Dial(t.Context(), l.Addr().String(), mms.DialOptions{Timeout: 2 * time.Second,
		OnReport: func(r mms.InformationReport) { reports <- r }, OnEvent: func(n mms.EventNotification) { events <- n }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if neg := c.Negotiated(); neg.MaxServOutstandingCalled != 1 || neg.NestingLevel != 5 || !c.Supports(mms.SvcRead) ||
		c.Supports(mms.SvcWrite) || !neg.ParameterCBB.Get(mms.CBBVnam) || neg.ParameterCBB.Get(mms.CBBStr1) {
		t.Errorf("negotiated = %+v", neg)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.ReadOne(t.Context(), mms.VMDName("X")); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if most.Load() != 1 {
		t.Errorf("%d requests were outstanding at once", most.Load())
	}
	select {
	case n := <-events:
		if n.Condition != mms.VMDName("C") {
			t.Errorf("event = %+v", n)
		}
	case <-time.After(2 * time.Second):
		t.Error("no event notification")
	}
	select {
	case r := <-reports:
		if r.Results[0].Data.Int != 1 {
			t.Errorf("report = %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Error("no information report")
	}
}
