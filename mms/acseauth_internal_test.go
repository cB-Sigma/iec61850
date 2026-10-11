package mms

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850/internal/testpki"
)

// testIdentity is a StaticIdentity for a new leaf of ca.
func testIdentity(ca *testpki.CA, name string) *StaticIdentity {
	leaf := ca.MustIssue(testpki.Leaf{Name: name, RSABits: 2048})
	return &StaticIdentity{Certificates: []*x509.Certificate{leaf.Cert}, Key: leaf.Key, Roots: ca.Pool()}
}

func testAuth(t *testing.T, offer bool, now func() time.Time) (*CertAuth, *testpki.Recorder) {
	t.Helper()
	ca, err := testpki.NewCA("acse root")
	if err != nil {
		t.Fatal(err)
	}
	rec := &testpki.Recorder{}
	a, err := NewCertAuth(testIdentity(ca, "acse"), offer, AuthOptions{Subject: "acse", Auditor: rec, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return a, rec
}

// The AARQ carries the authentication functional unit, the mechanism name
// 1.0.840.0.1.0.1.1 and a certificate-based authentication value in the
// external alternative; the identification is present exactly when the
// mmsAuthenticationAS context is proposed; the signature is RSASSA-PKCS1
// v1.5 with SHA-256 over the GeneralizedTime contents octets.
// Covers: SIG-SEC-731, SIG-SEC-732, SIG-SEC-733, SIG-SEC-745
func TestACSEAuthAARQEncoding(t *testing.T) {
	for _, offer := range []bool{false, true} {
		a, _ := testAuth(t, offer, nil)
		p := Params{Auth: a}.withDefaults()
		rq, err := aarq(p, InitiateRequest())
		if err != nil {
			t.Fatal(err)
		}
		f, err := acseFields(rq, 0x60)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(f[0x8a].Val, []byte{7, 0x80}) {
			t.Errorf("sender-acse-requirements %x", f[0x8a].Val)
		}
		// 1.0.840.0.1.0.1.1: 40, 840 in base 128, then 0 1 0 1 1.
		if want := []byte{0x28, 0x86, 0x48, 0, 1, 0, 1, 1}; !bytes.Equal(f[0x8b].Val, want) {
			t.Errorf("mechanism-name %x, want %x", f[0x8b].Val, want)
		}
		v, err := decodeAuthValue(f[0xac].Val)
		if err != nil {
			t.Fatal(err)
		}
		if (v.pci == ctxAuth) != offer {
			t.Errorf("offer %v: identification %d", offer, v.pci)
		}
		if !bytes.Equal(v.cert, a.Certificate().Raw) {
			t.Error("the certificate is not ours")
		}
		if !regexp.MustCompile(`^\d{14}(\.\d{1,3})?Z$`).Match(v.time) {
			t.Errorf("time %q", v.time)
		}
		h := sha256.Sum256(v.time)
		if err := rsa.VerifyPKCS1v15(a.Certificate().PublicKey.(*rsa.PublicKey), crypto.SHA256, h[:], v.signature); err != nil {
			t.Errorf("signature: %v", err)
		}
		cp := cpType(p, rq)
		if len(cp) <= 512 {
			// The CONNECT then carries it as extended user data (10.3, G.3),
			// which the round trip tests exercise.
			t.Errorf("a %d-octet CP PPDU does not test extended user data", len(cp))
		}
		ctxs := proposedContexts(cp)
		has := false
		for _, c := range ctxs {
			has = has || (c.id == ctxAuth && c.abstract == OIDAuthSyntax)
		}
		if has != offer {
			t.Errorf("offer %v: contexts %+v", offer, ctxs)
		}
		// The accept answers every proposed context.
		cpa := cpaType([]byte{0, 0, 0, 1}, ctxs, aare(ACSEAccepted, 0, nil, nil))
		e, _, _ := Parse(cpa)
		kids, _ := e.Children()
		items, _ := kids[1].Children()
		res, _ := items[1].Children()
		if len(res) != len(ctxs) {
			t.Errorf("%d results for %d contexts", len(res), len(ctxs))
		}
	}
}

// A value is accepted once: the same time from the same certificate within
// ten minutes is a replay; a changed signature fails; a time outside the
// window fails; each failure is an event.
// Covers: SIG-SEC-737, SIG-SEC-738
func TestACSEAuthValueChecks(t *testing.T) {
	now := time.Now()
	a, rec := testAuth(t, false, func() time.Time { return now })
	raw, err := a.value(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.check(raw, "peer"); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := a.check(raw, "peer"); !errors.Is(err, ErrAuthentication) || len(rec.Find(EvAuthReplay, "acse")) != 1 {
		t.Errorf("replay: %v", err)
	}
	now = now.Add(time.Second)
	raw, _ = a.value(0)
	v, _ := decodeAuthValue(raw)
	v.signature[10] ^= 1
	if _, err := a.check(encodeAuthValue(v), "peer"); err == nil || len(rec.Find(EvAuthSignature, "acse")) != 1 {
		t.Errorf("bad signature: %v", err)
	}
	v.signature[10] ^= 1
	now = now.Add(AuthWindow + time.Minute) // the value is now 11 minutes old
	if _, err := a.check(encodeAuthValue(v), "peer"); err == nil || len(rec.Find(EvAuthTime, "acse")) != 1 {
		t.Errorf("stale time: %v", err)
	}
	// Only the accepted value is remembered.
	if n := len(a.seen); n != 1 {
		t.Errorf("%d remembered values", n)
	}
	big := authValue{cert: make([]byte, MaxAuthCertificate+1), time: []byte("20260101000000Z"), signature: []byte{1}}
	if _, err := a.check(encodeAuthValue(big), "peer"); err == nil || len(rec.Find(EvAuthCertSize, "acse")) != 1 {
		t.Errorf("large certificate: %v", err)
	}
	if _, err := a.check([]byte{0xa0, 0x00}, "peer"); err == nil || len(rec.Find(EvAuthValueInvalid, "acse")) != 1 {
		t.Errorf("charstring alternative: %v", err)
	}
}

// Covers: SIG-SEC-733
func TestACSEAuthTime(t *testing.T) {
	ts := time.Date(2026, 9, 24, 10, 11, 12, 340_000_000, time.UTC)
	if got := string(authTime(ts)); got != "20260924101112.34Z" {
		t.Errorf("authTime = %s", got)
	}
	if got := string(authTime(ts.Truncate(time.Second))); got != "20260924101112Z" {
		t.Errorf("authTime whole seconds = %s", got)
	}
	for in, want := range map[string]time.Time{
		"20260924101112.34Z": ts, "20260924101112,34Z": ts, "20260924101112Z": ts.Truncate(time.Second),
		"202609241011Z": time.Date(2026, 9, 24, 10, 11, 0, 0, time.UTC),
	} {
		got, err := parseAuthTime([]byte(in))
		if err != nil || !got.Equal(want) {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"20260924101112", "2026-09-24T10:11:12Z", "20260924101112.Z", "20261324101112Z"} {
		if _, err := parseAuthTime([]byte(bad)); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
}
