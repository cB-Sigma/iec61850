package mms

import (
	"errors"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850/internal/testpki"
)

type e2ePKI struct{ ca *testpki.CA }

func newE2EPKI(t *testing.T) *e2ePKI {
	t.Helper()
	ca, err := testpki.NewCA("e2e root")
	if err != nil {
		t.Fatal(err)
	}
	return &e2ePKI{ca: ca}
}

func (k *e2ePKI) e2e(t *testing.T, server bool, s E2EOptions, now func() time.Time) *E2E {
	t.Helper()
	a, err := NewCertAuth(testIdentity(k.ca, map[bool]string{true: "server", false: "client"}[server]), false, AuthOptions{Subject: "test", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewE2E(a, s)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// pair runs a handshake in memory and returns both sessions.
func pair(t *testing.T, ce, se *E2E) (*e2eSession, *e2eSession) {
	t.Helper()
	hs, req, err := ce.clientHello([]byte{0xa8, 0}, 3, 7, false)
	if err != nil {
		t.Fatal(err)
	}
	rq, _, _ := Parse(req)
	shs, err := se.serverCheck(rq, 3, 7, "client")
	if err != nil {
		t.Fatal(err)
	}
	acc, ss, err := shs.accept([]byte{0xa9, 0}, false)
	if err != nil {
		t.Fatal(err)
	}
	ae, _, _ := Parse(acc)
	resp, cs, err := hs.finish(ae, "server", false)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != string([]byte{0xa9, 0}) || string(shs.initiate) != string([]byte{0xa8, 0}) {
		t.Fatalf("initiate carried as %x / %x", shs.initiate, resp)
	}
	return cs, ss
}

func roundTrip(t *testing.T, from, to *e2eSession, pdu []byte) {
	t.Helper()
	b, err := from.wrap(pdu)
	if err != nil {
		t.Fatal(err)
	}
	got, err := to.unwrap(b)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if string(got) != string(pdu) {
		t.Fatalf("got %x want %x", got, pdu)
	}
}

func wantDiag(t *testing.T, err error, diag int, alarmEv string) {
	t.Helper()
	var ee *E2EError
	if !errors.As(err, &ee) {
		t.Fatalf("error %v is not an E2E error", err)
	}
	if ee.Alarm != alarmEv || (alarmEv == "" && ee.Diag != diag) {
		t.Fatalf("error %v: want diagnostic %d alarm %q", err, diag, alarmEv)
	}
}

// Handshake and data transfer for every ICV and encryption choice and
// both DH groups (13.1, 13.2, 13.3.1.2, 13.3.1.3).
// Covers: SIG-IPE-2914, SIG-IPE-2915
func TestE2ESessions(t *testing.T) {
	k := newE2EPKI(t)
	for _, c := range []E2EOptions{
		{ICV: []string{"hmac-sha3-256"}}, {ICV: []string{"kmac256"}}, {ICV: []string{"kmac256"}, DHGroup: 14},
		{Encryption: "aes128-cbc"}, {Encryption: "aes256-cbc", ICV: []string{"kmac256"}}, {Encryption: "aes256-gcm"},
	} {
		cs, ss := pair(t, k.e2e(t, false, c, nil), k.e2e(t, true, c, nil))
		if cs.assoID != ss.assoID || cs.icvAlg != ss.icvAlg || cs.enc != ss.enc {
			t.Fatalf("%+v: sessions differ %s/%s", c, cs.assoID, ss.assoID)
		}
		for i := 0; i < 3; i++ {
			roundTrip(t, cs, ss, []byte{0xa0, 3, 2, 1, byte(i)})
			roundTrip(t, ss, cs, []byte{0xa1, 3, 2, 1, byte(i)})
		}
	}
}

// Key renewal (13.3.2): the client's rekey, the server's changedKey,
// then traffic on the new keys; a second rekey before changedKey and a
// changedKey without a rekey are refused (14.4.3 h, i).
// Covers: SIG-IPE-2916
func TestE2ERekey(t *testing.T) {
	k := newE2EPKI(t)
	for _, c := range []E2EOptions{{}, {Encryption: "aes256-gcm"}, {Encryption: "aes128-cbc"}} {
		cs, ss := pair(t, k.e2e(t, false, c, nil), k.e2e(t, true, c, nil))
		old := cs.send
		cs.forceRekey()
		roundTrip(t, cs, ss, []byte{0xa0, 0})
		if ss.pendingSend == nil || !cs.rekeyWait {
			t.Fatal("no rekey pending")
		}
		roundTrip(t, cs, ss, []byte{0xa0, 1}) // client already on the new keys
		roundTrip(t, ss, cs, []byte{0xa1, 0}) // changedKey, old keys
		if cs.rekeyWait || ss.pendingSend != nil || string(cs.recv.icvS)+string(cs.recv.encS) == string(old.icvS)+string(old.encS) {
			t.Fatal("keys not changed")
		}
		roundTrip(t, ss, cs, []byte{0xa1, 1})
		roundTrip(t, cs, ss, []byte{0xa0, 2})
	}
	cs, ss := pair(t, k.e2e(t, false, E2EOptions{}, nil), k.e2e(t, true, E2EOptions{}, nil))
	cs.forceRekey()
	roundTrip(t, cs, ss, []byte{0xa0, 0})
	cs.rekeyWait = false
	cs.forceRekey()
	b, _ := cs.wrap([]byte{0xa0, 1})
	_, err := ss.unwrap(b)
	wantDiag(t, err, DDUnexpectedDHKey, "")
	cs2, ss2 := pair(t, k.e2e(t, false, E2EOptions{}, nil), k.e2e(t, true, E2EOptions{}, nil))
	ss2.pendingSend = &ss2.send
	b, _ = ss2.wrap([]byte{0xa1, 0})
	_, err = cs2.unwrap(b)
	wantDiag(t, err, DDUnexpectedChanged, "")
}

// Data transfer checks of 14.4: a changed ICV, a replay, a sequence gap,
// another ICV algorithm, clear data when encryption was selected, a time
// out of the window; and the DtSecAbort sent then is signed.
// Covers: SIG-IPE-2917
func TestE2EDataTransferChecks(t *testing.T) {
	k := newE2EPKI(t)
	cs, ss := pair(t, k.e2e(t, false, E2EOptions{}, nil), k.e2e(t, true, E2EOptions{}, nil))
	b, _ := cs.wrap([]byte{0xa0, 0})
	bad := append([]byte{}, b...)
	bad[len(bad)-1] ^= 1
	_, err := ss.unwrap(bad)
	wantDiag(t, err, 0, EvE2EICV)
	if _, err := ss.unwrap(b); err != nil {
		t.Fatal(err)
	}
	_, err = ss.unwrap(b)
	wantDiag(t, err, 0, EvE2EReplay)

	cs, ss = pair(t, k.e2e(t, false, E2EOptions{}, nil), k.e2e(t, true, E2EOptions{}, nil))
	first, _ := cs.wrap([]byte{0xa0, 0})
	if _, err := ss.unwrap(first); err != nil {
		t.Fatal(err)
	}
	cs.mu.Lock()
	cs.sendSeq++ // skip one within the same time value
	cs.mu.Unlock()
	cs.sendTime = string(e2eTime(cs.e.auth.now())) // keep the time
	gap, _ := cs.wrap([]byte{0xa0, 1})
	if _, err := ss.unwrap(gap); err == nil {
		t.Fatal("a sequence gap was accepted")
	} else {
		var ee *E2EError
		if errors.As(err, &ee) && ee.Alarm == "" && ee.Diag != DDInvalidSequence {
			t.Fatalf("gap: %v", err)
		}
	}

	cs, ss = pair(t, k.e2e(t, false, E2EOptions{ICV: []string{"kmac256", "hmac-sha3-256"}}, nil), k.e2e(t, true, E2EOptions{}, nil))
	cs.icvAlg = oidHMACSHA3_256
	if ss.icvAlg != oidKMACSHAKE256 {
		t.Fatalf("server chose %s, want the client's first choice", ss.icvAlg)
	}
	b, _ = cs.wrap([]byte{0xa0, 0})
	_, err = ss.unwrap(b)
	wantDiag(t, err, 0, EvE2EICVAlgorithm)

	ce, se := k.e2e(t, false, E2EOptions{Encryption: "aes128-cbc"}, nil), k.e2e(t, true, E2EOptions{Encryption: "aes128-cbc"}, nil)
	cs, ss = pair(t, ce, se)
	cs.enc = ""
	b, _ = cs.wrap([]byte{0xa0, 0})
	_, err = ss.unwrap(b)
	wantDiag(t, err, DDEncryptionRequired, "")

	late := func() time.Time { return time.Now().Add(11 * time.Minute) }
	cs, ss = pair(t, k.e2e(t, false, E2EOptions{}, nil), k.e2e(t, true, E2EOptions{}, nil))
	cs.e = k.e2e(t, false, E2EOptions{}, late)
	cs.e.auth = ss.e.auth // keep keys; only the clock differs
	cs.e.auth = &CertAuth{chain: cs.e.auth.chain, key: cs.e.auth.key, o: AuthOptions{Now: late}, log: cs.e.auth.log, id: cs.e.auth.id}
	b, _ = cs.wrap([]byte{0xa0, 0})
	_, err = ss.unwrap(b)
	wantDiag(t, err, DDProtocolError, "")

	// The DtSecAbort is a signed SecPDU with the diagnostic.
	ab := ss.dtAbort(dtErr(DDInvalidSequence, "x"))
	f, _ := acseFields(ab, 0x64)
	_, sec, err := e2eFromExternal(f[0xbe])
	if err != nil || sec.Tag != 0xa1 {
		t.Fatalf("abort %x: %v", ab, err)
	}
	fields, _, _, verr := cs.e.verifySigned(sec, "server", false)
	if verr != nil || len(fields) != 2 || fields[1].Tag != 0x0a || fields[1].Val[0] != DDInvalidSequence {
		t.Fatalf("DtSecAbort %v %v", fields, verr)
	}
}

// Handshake checks of 14.3: a changed signature, a replayed request, a
// time out of the window, algorithm and encryption mismatches with their
// diagnostics.
// Covers: SIG-IPE-2918
func TestE2EHandshakeChecks(t *testing.T) {
	k := newE2EPKI(t)
	hello := func(ce *E2E) Elem {
		_, req, err := ce.clientHello([]byte{0xa8, 0}, 3, 7, false)
		if err != nil {
			t.Fatal(err)
		}
		e, _, _ := Parse(req)
		return e
	}
	se := k.e2e(t, true, E2EOptions{}, nil)
	ce := k.e2e(t, false, E2EOptions{}, nil)
	req := hello(ce)
	raw := rawOf(req)
	raw[len(raw)-3] ^= 0xff
	tampered, _, _ := Parse(raw)
	_, err := se.serverCheck(tampered, 3, 7, "c")
	wantDiag(t, err, 0, EvE2ESignature)
	if _, err := se.serverCheck(req, 3, 7, "c"); err != nil {
		t.Fatal(err)
	}
	_, err = se.serverCheck(req, 3, 7, "c")
	wantDiag(t, err, 0, EvE2EReplay)

	late := k.e2e(t, false, E2EOptions{}, func() time.Time { return time.Now().Add(-11 * time.Minute) })
	_, err = se.serverCheck(hello(late), 3, 7, "c")
	wantDiag(t, err, HDInvalidTime, "")

	for _, c := range []struct {
		cl, sv E2EOptions
		diag   int
	}{
		{E2EOptions{ICV: []string{"hmac-sha3-256"}}, E2EOptions{ICV: []string{"kmac256"}}, HDICVNotSupported},
		{E2EOptions{}, E2EOptions{Encryption: "aes128-cbc", RequireEncryption: true}, HDEncryptionRequired},
		{E2EOptions{Encryption: "aes128-cbc"}, E2EOptions{}, HDEncryptionNotRequired},
		{E2EOptions{Encryption: "aes256-gcm"}, E2EOptions{Encryption: "aes256-cbc"}, HDEncrModeAEANotSupp},
		{E2EOptions{Encryption: "aes256-gcm"}, E2EOptions{}, HDAEASelectButEncNotSupp},
		{E2EOptions{Encryption: "aes256-cbc"}, E2EOptions{Encryption: "aes256-gcm"}, HDAEIsRequired},
	} {
		_, err := k.e2e(t, true, c.sv, nil).serverCheck(hello(k.e2e(t, false, c.cl, nil)), 3, 7, "c")
		wantDiag(t, err, c.diag, "")
	}
	// A peer certificate from another CA: invalid certification path.
	other := newE2EPKI(t)
	_, err = se.serverCheck(hello(other.e2e(t, false, E2EOptions{}, nil)), 3, 7, "c")
	wantDiag(t, err, HDInvalidCertPath, "")
	// The rejection is a signed HandshakeSecReject with the diagnostic.
	rj, _, _ := Parse(se.reject("12", err))
	fields, _, _, verr := ce.verifySigned(rj, "s", true)
	if rj.Tag != 0xa3 || verr != nil || fields[1].Val[0] != HDInvalidCertPath {
		t.Fatalf("reject %v %v", fields, verr)
	}
}

// Settings limits: the rekey interval (15 min to 24 h), algorithms.
func TestE2EOptions(t *testing.T) {
	for _, s := range []E2EOptions{{RekeyInterval: "10m"}, {RekeyInterval: "25h"}, {ICV: []string{"hmac-sha256"}}, {Encryption: "des"}, {DHGroup: 5},
		{RequireEncryption: true}} {
		k := newE2EPKI(t)
		a, err := NewCertAuth(testIdentity(k.ca, "x"), false, AuthOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewE2E(a, s); err == nil {
			t.Errorf("%+v accepted", s)
		}
	}
}
