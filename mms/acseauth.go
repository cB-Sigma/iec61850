package mms

// ACSE peer-entity authentication with certificates: the A-security
// profile of IEC 62351-4:2018+AMD1:2020 clause 11 (formerly the A-profile
// of IEC TS 62351-4:2007), used by IEC 61850-8-1 and ICCP (TASE.2)
// associations.
//
// Both AARQ and AARE carry the authentication functional unit bit in their
// ACSE requirements (11.1.4.1), the mechanism name 1.0.840.0.1.0.1.1
// (11.1.4.3) and an authentication value of the external alternative whose
// content is MMS-Authentication-value certificate-based: the sender's DER
// certificate (at most 8192 octets), a GeneralizedTime, and an
// RSASSA-PKCS1-v1_5 SHA-256 signature over the time's DER contents octets
// (11.1.4.4, 11.2.2, Annex A). The identification (indirect reference)
// is present only when the mmsAuthenticationAS abstract syntax
// 1.0.840.0.1.1.4.1 is in the presentation context list (11.1.3).
//
// The receiver refuses a missing mechanism name with an AARE (server,
// diagnostic authentication-mechanism-name-required) or an ABRT from the
// ACSE service provider (client), and an invalid certificate, a time more
// than ten minutes from its clock, a time seen twice within ten minutes,
// or a bad signature with a presentation provider abort (11.2.3.2,
// 11.2.4.2).

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cB-Sigma/iotsec"
)

// Object identifiers of the A-security profile.
const (
	// OIDAuthMechanism is the mechanism-name of AARQ and AARE (11.1.4.3).
	OIDAuthMechanism = "1.0.840.0.1.0.1.1"
	// OIDAuthSyntax is the mmsAuthenticationAS abstract syntax (11.1.3).
	OIDAuthSyntax = "1.0.840.0.1.1.4.1"
)

const (
	ctxAuth = 5 // our presentation context for mmsAuthenticationAS (odd, 10.4.1)
	// AuthWindow is how far the time of an authentication value may be
	// from ours, and how long a time value is remembered (11.2.3.2 d, e).
	AuthWindow = 10 * time.Minute
	// MaxAuthCertificate is the largest certificate exchanged by ACSE
	// (6.2.6, 11.2.2 a).
	MaxAuthCertificate = 8192
)

// ABRT abort sources and diagnostics (ITU-T X.227; IEC 62351-4 Annex I).
const (
	AbortSourceUser     = 0
	AbortSourceProvider = 1

	AbortDiagNoReason         = 1
	AbortDiagProtocolError    = 2
	AbortDiagMechUnrecognised = 3
	AbortDiagMechRequired     = 4
	AbortDiagAuthFailure      = 5
	AbortDiagAuthRequired     = 6
)

// Security event mnemonics of ACSE authentication. IEC 62351-4 names no
// events for the A-security profile (only the certificate events of 6.2.6
// to 6.2.8, which the certificate check records under the IEC 62351-3
// profile's mnemonics); these are ours.
const (
	EvAuthSuccess      = "ACSE_AUTH_SUCCESS"
	EvAuthMechMissing  = "ACSE_AUTH_MECH_MISSING"
	EvAuthMechUnknown  = "ACSE_AUTH_MECH_UNKNOWN"
	EvAuthValueInvalid = "ACSE_AUTH_VALUE_INVALID"
	EvAuthCertSize     = "ACSE_AUTH_CERT_SIZE"
	EvAuthCertInvalid  = "ACSE_AUTH_CERT_INVALID"
	EvAuthTime         = "ACSE_AUTH_TIME"
	EvAuthReplay       = "ACSE_AUTH_REPLAY"
	EvAuthSignature    = "ACSE_AUTH_SIGNATURE"
)

var authSeverity = map[string]string{
	EvAuthSuccess: "notice", EvAuthMechMissing: "alarm", EvAuthMechUnknown: "alarm", EvAuthValueInvalid: "alarm",
	EvAuthCertSize: "warning", EvAuthCertInvalid: "alarm", EvAuthTime: "alarm", EvAuthReplay: "alarm", EvAuthSignature: "alarm",
}

var authAuditor atomic.Pointer[authAuditorBox]

type authAuditorBox struct{ a iotsec.Auditor }

// SetAuditor installs the security event log ACSE authentication and E2E
// security events are recorded to when AuthOptions.Auditor is nil (nil:
// the slog logger only).
func SetAuditor(a iotsec.Auditor) {
	if a == nil {
		authAuditor.Store(nil)
		return
	}
	authAuditor.Store(&authAuditorBox{a})
}

// AuthIdentity is the certificate side of ACSE authentication and E2E
// security, which the application provides: this side's certificate and
// key (KeySource; asked again by CertAuth.Reload after a renewal) and the
// check of a peer's certificate (path to the trust anchors, validity,
// revocation, local policy). StaticIdentity is a plain implementation.
type AuthIdentity interface {
	iotsec.KeySource
	// VerifyPeer checks the certificate a peer presented (chain, leaf
	// first; ACSE carries the leaf only); peer names it in events. An
	// error refuses the authentication.
	VerifyPeer(ctx context.Context, chain []*x509.Certificate, peer string) error
}

// AuthOptions name who uses the authentication, for its events.
type AuthOptions struct {
	Subject, Tenant string
	Log             *slog.Logger
	Now             func() time.Time
	// Auditor receives the security events (nil: the one SetAuditor
	// installed, if any).
	Auditor iotsec.Auditor
}

// CertAuth performs certificate-based ACSE authentication for one side. It
// is safe for concurrent use; a server shares one across its associations,
// so the replay check covers them all.
type CertAuth struct {
	offer bool
	id    AuthIdentity
	chain []*x509.Certificate
	key   crypto.Signer
	o     AuthOptions
	log   *slog.Logger

	mu   sync.Mutex
	seen map[string]time.Time // certificate hash + time value -> when first seen
}

// NewCertAuth uses this side's identity (an RSA key of at least 2048 bits,
// IEC 62351-4 11.2.2 c; G.2 asks for a certificate other than the TLS one)
// and its peer check. offerSyntax proposes the mmsAuthenticationAS
// presentation context (11.1.3, "should"; some older peers refuse it); a
// server always accepts it when proposed.
func NewCertAuth(id AuthIdentity, offerSyntax bool, o AuthOptions) (*CertAuth, error) {
	if id == nil {
		return nil, errors.New("acseAuth: no identity")
	}
	a := &CertAuth{offer: offerSyntax, id: id, o: o, log: o.Log, seen: map[string]time.Time{}}
	if a.log == nil {
		a.log = slog.Default()
	}
	chain, key, err := a.load(context.Background())
	if err != nil {
		return nil, err
	}
	if len(chain[0].Raw) > MaxAuthCertificate {
		return nil, fmt.Errorf("acseAuth: the certificate is %d octets; at most %d (IEC 62351-4 6.2.6)", len(chain[0].Raw), MaxAuthCertificate)
	}
	a.chain, a.key = chain, key
	return a, nil
}

// load reads and checks the identity.
func (a *CertAuth) load(ctx context.Context) ([]*x509.Certificate, crypto.Signer, error) {
	ident, err := a.id.Identity(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("acseAuth: %w", err)
	}
	if len(ident.Certificates) == 0 || ident.Key == nil {
		return nil, nil, errors.New("acseAuth: the identity has no certificate or no key")
	}
	pub, ok := ident.Certificates[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("acseAuth: the certificate needs an RSA key (sha256WithRSAEncryption, IEC 62351-4 11.2.2 c)")
	}
	if pub.N.BitLen() < 2048 {
		return nil, nil, fmt.Errorf("acseAuth: the RSA key has %d bits; at least 2048 (IEC 62351-4 11.2.2 c)", pub.N.BitLen())
	}
	return ident.Certificates, ident.Key, nil
}

// Identity is the identity the authentication was built with.
func (a *CertAuth) Identity() AuthIdentity { return a.id }

// Certificate is this side's certificate.
func (a *CertAuth) Certificate() *x509.Certificate {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.chain[0]
}

// Reload asks the identity again, after the application renewed the
// certificate and key (IEC 62351-9 7.6), for the associations that follow.
func (a *CertAuth) Reload(ctx context.Context) error {
	ident, err := a.id.Identity(ctx)
	if err != nil {
		return fmt.Errorf("acseAuth: %w", err)
	}
	if len(ident.Certificates) == 0 || ident.Key == nil {
		return errors.New("acseAuth: the identity has no certificate or no key")
	}
	if pub, ok := ident.Certificates[0].PublicKey.(*rsa.PublicKey); !ok || pub.N.BitLen() < 2048 {
		return errors.New("acseAuth: the renewed certificate needs an RSA key of at least 2048 bits (IEC 62351-4 11.2.2 c)")
	}
	a.mu.Lock()
	a.chain, a.key = ident.Certificates, ident.Key
	a.mu.Unlock()
	return nil
}

func (a *CertAuth) now() time.Time {
	if a.o.Now != nil {
		return a.o.Now()
	}
	return time.Now()
}

func (a *CertAuth) event(mnemonic, peer string, detail map[string]string) {
	sev := authSeverity[mnemonic]
	d := map[string]string{"severity": sev, "clause": "IEC 62351-4 11.2"}
	for k, v := range detail {
		if v != "" {
			d[k] = v
		}
	}
	attrs := []any{"event", mnemonic, "subject", a.o.Subject, "peer", peer}
	for k, v := range detail {
		attrs = append(attrs, k, v)
	}
	msg := "IEC 62351-4 ACSE authentication event"
	if detail["method"] == "e2e" {
		msg = "IEC 62351-4 E2E security event"
	}
	switch sev {
	case "alarm":
		a.log.Error(msg, attrs...)
	case "warning":
		a.log.Warn(msg, attrs...)
	default:
		a.log.Info(msg, attrs...)
	}
	method := "acse"
	if m := detail["method"]; m != "" {
		method = m
		delete(d, "method")
	}
	rec := a.o.Auditor
	if rec == nil {
		if b := authAuditor.Load(); b != nil {
			rec = b.a
		}
	}
	if rec == nil {
		return
	}
	out := iotsec.OutcomeFailure
	if sev == "notice" {
		out = iotsec.OutcomeSuccess
	}
	rec.RecordSecurity(context.Background(), iotsec.SecurityEvent{Tenant: a.o.Tenant, Category: "communication",
		Event: strings.ToLower(mnemonic), Outcome: out, Actor: "system", Subject: a.o.Subject, Peer: peer, Method: method, Detail: d})
}

// authTime renders t in UTC as DER GeneralizedTime contents
// (YYYYMMDDHHMMSS, a fraction of seconds without trailing zeros, Z).
func authTime(t time.Time) []byte {
	s := t.UTC().Format("20060102150405.000")
	s = strings.TrimRight(s, "0")
	s = strings.TrimSuffix(s, ".")
	return []byte(s + "Z")
}

// parseAuthTime reads GeneralizedTime contents in UTC
// (YYYYMMDDHH[MM[SS]][.fff or ,fff]Z).
func parseAuthTime(b []byte) (time.Time, error) {
	s := string(b)
	if !strings.HasSuffix(s, "Z") {
		return time.Time{}, fmt.Errorf("time %q is not UTC (Z)", s)
	}
	s = strings.TrimSuffix(s, "Z")
	frac := ""
	if i := strings.IndexAny(s, ".,"); i >= 0 {
		s, frac = s[:i], s[i+1:]
		if frac == "" {
			return time.Time{}, fmt.Errorf("time %q has an empty fraction", b)
		}
	}
	layouts := map[int]string{10: "2006010215", 12: "200601021504", 14: "20060102150405"}
	layout, ok := layouts[len(s)]
	if !ok {
		return time.Time{}, fmt.Errorf("time %q is not a GeneralizedTime", b)
	}
	t, err := time.ParseInLocation(layout, s, time.UTC)
	if err != nil {
		return time.Time{}, fmt.Errorf("time %q: %w", b, err)
	}
	if frac != "" {
		for _, c := range frac {
			if c < '0' || c > '9' {
				return time.Time{}, fmt.Errorf("time %q has a bad fraction", b)
			}
		}
		f, _ := strconv.ParseFloat("0."+frac, 64)
		unit := time.Second
		switch len(s) {
		case 10:
			unit = time.Hour
		case 12:
			unit = time.Minute
		}
		t = t.Add(time.Duration(f * float64(unit)))
	}
	return t, nil
}

// authValue is a decoded MMS-Authentication-value (certificate-based).
type authValue struct {
	cert      []byte
	time      []byte
	signature []byte
	pci       int // indirect reference, 0 when absent
}

// value builds this side's Authentication-value (the contents of
// calling- or responding-authentication-value): the external alternative
// [2], with the identification when the authentication syntax is in use.
func (a *CertAuth) value(pci int) ([]byte, error) {
	ts := authTime(a.now())
	h := sha256.Sum256(ts)
	a.mu.Lock()
	key, cert := a.key, a.chain[0].Raw
	a.mu.Unlock()
	sig, err := key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("acseAuth: signing: %w", err)
	}
	return encodeAuthValue(authValue{cert: cert, time: ts, signature: sig, pci: pci}), nil
}

func encodeAuthValue(v authValue) []byte {
	mmsAuth := T(0xa0, T(0x80, v.cert), T(0x81, v.time), T(0x82, v.signature)) // certificate-based [0]
	var parts [][]byte
	if v.pci != 0 {
		parts = append(parts, Int(0x02, int64(v.pci)))
	}
	parts = append(parts, T(0xa0, mmsAuth)) // single-ASN1-type [0]
	return T(0xa2, parts...)                // external [2] IMPLICIT
}

// decodeAuthValue reads the contents of calling- or
// responding-authentication-value.
func decodeAuthValue(b []byte) (authValue, error) {
	var v authValue
	e, rest, err := Parse(b)
	if err != nil {
		return v, err
	}
	if len(rest) != 0 {
		return v, errors.New("trailing octets after the authentication value")
	}
	if e.Tag != 0xa2 {
		return v, fmt.Errorf("authentication value alternative %#x, not external [2]", e.Tag)
	}
	kids, err := e.Children()
	if err != nil {
		return v, err
	}
	var enc *Elem
	for i := range kids {
		switch kids[i].Tag {
		case 0x02:
			n, err := DecodeInt(kids[i].Val)
			if err != nil {
				return v, err
			}
			v.pci = int(n)
		case 0xa0:
			enc = &kids[i]
		case 0x06: // a direct reference is tolerated
		default:
			return v, fmt.Errorf("unexpected element %#x in the external", kids[i].Tag)
		}
	}
	if enc == nil {
		return v, errors.New("the external has no single-ASN1-type")
	}
	cb, rest, err := Parse(enc.Val)
	if err != nil {
		return v, err
	}
	if len(rest) != 0 || cb.Tag != 0xa0 {
		return v, fmt.Errorf("MMS-Authentication-value alternative %#x, not certificate-based [0]", cb.Tag)
	}
	fields, err := cb.Children()
	if err != nil {
		return v, err
	}
	for _, f := range fields {
		switch f.Tag {
		case 0x80:
			v.cert = f.Val
		case 0x81:
			v.time = f.Val
		case 0x82:
			v.signature = f.Val
		}
	}
	if v.cert == nil || v.time == nil || v.signature == nil {
		return v, errors.New("certificate-based needs a certificate, a time and a signature")
	}
	return v, nil
}

// authFailure is a failed check of a received authentication value; it
// ends the association with a presentation provider abort.
type authFailure struct {
	event, reason string
}

func (f *authFailure) Error() string { return "ACSE authentication failed: " + f.reason }

// ErrAuthentication is wrapped by errors of a failed ACSE authentication.
var ErrAuthentication = errors.New("ACSE authentication failed")

func (f *authFailure) Unwrap() error { return ErrAuthentication }

// check verifies a received authentication value (11.2.3.2 c to f,
// 11.2.4.2 c to f) and returns the peer's certificate.
func (a *CertAuth) check(raw []byte, peer string) (*x509.Certificate, error) {
	fail := func(ev, reason string, d map[string]string) (*x509.Certificate, error) {
		if d == nil {
			d = map[string]string{}
		}
		d["reason"] = reason
		a.event(ev, peer, d)
		return nil, &authFailure{event: ev, reason: reason}
	}
	v, err := decodeAuthValue(raw)
	if err != nil {
		return fail(EvAuthValueInvalid, err.Error(), nil)
	}
	if len(v.cert) > MaxAuthCertificate {
		return fail(EvAuthCertSize, fmt.Sprintf("the certificate is %d octets, above %d", len(v.cert), MaxAuthCertificate),
			map[string]string{"size": strconv.Itoa(len(v.cert))})
	}
	cert, err := x509.ParseCertificate(v.cert)
	if err != nil {
		return fail(EvAuthCertInvalid, "the certificate does not parse: "+err.Error(), nil)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.id.VerifyPeer(ctx, []*x509.Certificate{cert}, peer); err != nil {
		return fail(EvAuthCertInvalid, err.Error(), map[string]string{"certificate": cert.Subject.String()})
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 {
		return fail(EvAuthCertInvalid, "the certificate needs an RSA key of at least 2048 bits (11.2.2 c)",
			map[string]string{"certificate": cert.Subject.String()})
	}
	t, err := parseAuthTime(v.time)
	if err != nil {
		return fail(EvAuthTime, err.Error(), nil)
	}
	now := a.now()
	if d := now.Sub(t); d > AuthWindow || d < -AuthWindow {
		return fail(EvAuthTime, fmt.Sprintf("the time %s is %s from ours", v.time, d.Round(time.Second)),
			map[string]string{"time": string(v.time)})
	}
	h := sha256.Sum256(v.time)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], v.signature); err != nil {
		return fail(EvAuthSignature, "the signature over the time does not verify", map[string]string{"certificate": cert.Subject.String()})
	}
	// The same time value twice within the window is a replay (11.2.3.2 e).
	// It is remembered per certificate: two peers may sign the same second.
	fp := sha256.Sum256(cert.Raw)
	key := string(fp[:]) + string(v.time)
	a.mu.Lock()
	for k, at := range a.seen {
		if now.Sub(at) > AuthWindow {
			delete(a.seen, k)
		}
	}
	_, dup := a.seen[key]
	if !dup {
		a.seen[key] = now
	}
	a.mu.Unlock()
	if dup {
		return fail(EvAuthReplay, fmt.Sprintf("the time %s was already used within %s", v.time, AuthWindow),
			map[string]string{"time": string(v.time), "certificate": cert.Subject.String()})
	}
	a.event(EvAuthSuccess, peer, map[string]string{"certificate": cert.Subject.String(), "serial": cert.SerialNumber.String()})
	return cert, nil
}

// acseRequirementsAuth is the ACSE-requirements bit string with the
// authentication functional unit (bit 0) selected.
var acseRequirementsAuth = []byte{7, 0x80}

func hasAuthBit(e Elem) bool {
	return len(e.Val) >= 2 && e.Val[1]&0x80 != 0
}

// abrt builds an ACSE ABRT APDU.
func abrt(source, diag int) []byte {
	parts := [][]byte{Int(0x80, int64(source))}
	if diag != 0 {
		parts = append(parts, Int(0x81, int64(diag)))
	}
	return T(0x64, parts...)
}

// userAbort sends an A-ABORT (ABRT in a presentation ARU-PPDU in a session
// ABORT SPDU).
func (t *transport) userAbort(apdu []byte) error {
	aru := T(0xa0, pdv(ctxACSE, apdu)) // normal-mode-parameters
	return t.writeTSDU(spdu(spduAbort, sessParam(17, []byte{0x03}), sessParam(0xc1, aru)))
}

// providerAbort sends a P-ABORT (ARP-PPDU, reason not specified, in a
// session ABORT SPDU).
func (t *transport) providerAbort() error {
	arp := T(0x30, Int(0x80, 0))
	return t.writeTSDU(spdu(spduAbort, sessParam(17, []byte{0x01}), sessParam(0xc1, arp)))
}

func sameOID(e Elem, oid string) bool { return bytes.Equal(e.Val, OID(oid)) }
