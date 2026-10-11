package mms_test

import (
	"net"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

// The initiate request proposes the services and parameter CBBs of
// DialOptions.Capabilities; the server learns the called and calling
// addresses and the authentication mechanism and value of the AARQ.
// Covers: SIG-IPE-1913, SIG-IPE-1914
func TestDialCapabilitiesAndAssociationInfo(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan mms.Association, 1)
	go func() {
		nc, err := l.Accept()
		if err != nil {
			return
		}
		sc, err := mms.AcceptAssociation(nc, func(a mms.Association) (int, int, []byte) {
			got <- a
			resp, _ := mms.InitiateResponseTo(a.Initiate, mms.BasicServerCapabilities)
			return mms.ACSEAccepted, 0, resp
		})
		if err == nil {
			defer sc.Close()
			_, _ = sc.Receive()
		}
	}()
	caps := mms.Capabilities{MaxPDU: 65000, MaxOutstanding: 5, Nesting: 10, Parameters: []int{mms.CBBStr1, mms.CBBVnam},
		Services: []int{mms.SvcRead, mms.BitInformationReport, mms.BitConclude}}
	c, err := mms.Dial(t.Context(), l.Addr().String(), mms.DialOptions{Capabilities: &caps, Timeout: 3 * time.Second,
		Params: mms.Params{Password: "pw", LocalAPTitle: "1.3.9999.1", LocalAEQual: 7, RemoteAPTitle: "1.3.9999.2", RemoteAEQual: 12}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	a := <-got
	e, _, _ := mms.Parse(a.Initiate)
	ini, err := mms.DecodeInitiate(e)
	if err != nil {
		t.Fatal(err)
	}
	if !ini.Services.Get(mms.SvcRead) || ini.Services.Get(mms.SvcStatus) || ini.Services.Get(mms.SvcFileOpen) ||
		!ini.ParameterCBB.Get(mms.CBBVnam) || ini.ParameterCBB.Get(mms.CBBValt) {
		t.Errorf("proposed services %v parameters %v", ini.Services, ini.ParameterCBB)
	}
	if a.CallingAPTitle != "1.3.9999.1" || a.CallingAPTitleForm != 2 || a.CallingAEQualifier == nil || *a.CallingAEQualifier != 7 ||
		a.CalledAPTitle != "1.3.9999.2" || a.CalledAEQualifier == nil || *a.CalledAEQualifier != 12 {
		t.Errorf("titles %+v", a)
	}
	if string(a.CalledTSel) != "\x00\x01" || string(a.CalledSSel) != "\x00\x01" || string(a.CalledPSel) != "\x00\x00\x00\x01" {
		t.Errorf("called selectors %x %x %x", a.CalledTSel, a.CalledSSel, a.CalledPSel)
	}
	if a.AuthMechanism != "2.2.3.1" || a.Password != "pw" || len(a.AuthValue) == 0 {
		t.Errorf("authentication %q %q %x", a.AuthMechanism, a.Password, a.AuthValue)
	}
}
