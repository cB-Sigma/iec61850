package mms

// IEC 62351-4 end-to-end application security (E2E, clauses 13 to 15) in
// the OSI operational environment, protecting MMS (IEC 61850-8-1). The
// ASN.1 is that of the IEC 62351-4 machine-readable files 2025-11 (E2E-Security,
// OSI-Env, Virtual-API; read, not copied), which
// supersede Annex B where they differ (F-1566); the procedures are those
// of the 2020 text. Everything is BER, IMPLICIT TAGS.
//
// Association: the AARQ carries OSI-AssoReq (an EXTERNAL with the
// presentation context of e2eSecurityAS) holding a HandshakeReq whose
// signed tbs holds ClearToken1 and ApplData (the MMS initiate request);
// the AARE carries OSI-AssoRsp with HandshakeAcc (ApplData: the initiate
// response), ApplicationReject or HandshakeSecReject. Both sides sign the
// tbs contents (without its tag and length) with RSASSA-PKCS1-v1_5 and
// SHA-256 (rsaEncryption names no hash, F-1570), send a Diffie-Hellman
// public key (group 23, P-256, or group 14, MODP 2048) and derive the
// shared keys with HKDF-SHA256 (hmacWithSHA256): salt = SHA-256(tbs(acc)
// || SHA-256(tbs(req) || h0)), h0 32 zero octets (F-1571), IKM the DH
// secret, no info; the output is the client's then the server's ICV key
// (32 octets each), followed with separate encryption by the client's
// and the server's encryption key; with AES-256-GCM the two keys are the
// AEAD keys.
//
// Data transfer: every MMS PDU travels as DataTransfer (clearTransfer
// [0] or encrTransfer [1]) in the E2E presentation context. ClearToken2
// carries the association ID, the time and a sequence number (0 for the
// first message of a time value, then +1); the ICV (HMAC-SHA3-256 or
// KMAC256 with its RFC 8702 defaults, 512 bits) covers the tbp contents
// after any encryption; AES-CBC encrypts the encoded ApplData with PKCS
// #7 padding (F-1572) and a fresh IV in ClearToken2 iv; AES-256-GCM
// takes the 12-octet nonce from ClearToken2 iv and the encoded
// ClearToken2 as additional data, with no Authenticator. The receiver
// checks, in the order of 14.4, version, encryption, IV, ICV algorithm
// (alarm), ICV (alarm), time (10 min, not going back), replay (alarm) and
// sequence, and the key renewal rules; a failure ends the association
// with an ABRT carrying a signed DtSecAbort (no diagnostic after an
// alarm). Key renewal (13.3.2): the client sends a new DH public key in
// rekey at most every rekeyInterval (15 min to 24 h); both derive new
// keys from salt' = SHA-256(tbp(that PDU) || salt) and the new secret;
// the client uses them for its following PDUs, the server for the PDUs
// after the one in which it signals changedKey.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cB-Sigma/iotcrypto/kmac"
)

// Object identifiers of E2E security (clause 9, 15.2) and its algorithms.
const (
	OIDE2ESyntax     = "1.0.62351.4.1.2.1" // e2eSecurityAS
	OIDE2EMMSContext = "1.0.62351.4.2.1"   // e2eMmsAC
	oidRSAEncryption = "1.2.840.113549.1.1.1"
	oidSHA256RSA     = "1.2.840.113549.1.1.11"
	oidHMACSHA256    = "1.2.840.113549.2.9"
	oidHMACSHA3_256  = "2.16.840.1.101.3.4.2.14"
	oidKMACSHAKE256  = "2.16.840.1.101.3.4.2.20"
	oidAES128CBC     = "2.16.840.1.101.3.4.1.2"
	oidAES256CBC     = "2.16.840.1.101.3.4.1.42"
	oidAES256GCM     = "2.16.840.1.101.3.4.1.46"

	ctxE2E = 7 // our presentation context for e2eSecurityAS (odd, 10.4.1)

	// E2EProtocol is the pp of HandshakeReq for MMS of IEC 61850-8-1.
	E2EProtocol = "IEC 61850-8-1"
)

// HandshakeDiagnostics (machine-readable files 2025-11).
const (
	HDNoReason               = 0
	HDProtocolError          = 1
	HDProtectedNotSupported  = 2
	HDInvalidSignatureAlg    = 3
	HDUnexpectedVersion      = 4
	HDHMACNotSupported       = 5
	HDEncryptionNotRequired  = 6
	HDEncryptionRequired     = 7
	HDInvalidCertificate     = 8
	HDInvalidCertPath        = 9
	HDInvalidTime            = 10
	HDDHGroupNotSupported    = 11
	HDIllegalDHGroup         = 12
	HDICVNotSupported        = 13
	HDEncryptNotSupported    = 14
	HDAEANotSupported        = 15
	HDEncrModeAEANotSupp     = 17
	HDAEIsRequired           = 18
	HDAEASelectButEncNotSupp = 19
	HDInvalidAEAlgorithm     = 20
	HDSingleAERequired       = 21
	HDAENotUsed              = 22
	HDInvalidEncryptionAlg   = 23
	HDSingleEncryptRequired  = 24
	HDSingleICVRequired      = 25
)

// DtDiagnostics (machine-readable files 2025-11).
const (
	DDNoReason           = 0
	DDProtocolError      = 1
	DDUnexpectedVersion  = 2
	DDEncryptionNotSel   = 3
	DDEncryptionRequired = 4
	DDGMACNonceRequired  = 5
	DDInvalidSequence    = 6
	DDAESIVRequired      = 7
	DDUnexpectedDHKey    = 8
	DDUnexpectedChanged  = 9
)

// Security event mnemonics of E2E security (ours; IEC 62351-4 names the
// alarm conditions of 14.3 and 14.4 but no mnemonics).
const (
	EvE2EAssociated   = "E2E_ASSOCIATED"
	EvE2EHandshake    = "E2E_HANDSHAKE_REFUSED"
	EvE2ESignature    = "E2E_SIGNATURE_INVALID"
	EvE2EReplay       = "E2E_REPLAY"
	EvE2EICV          = "E2E_ICV_INVALID"
	EvE2EICVAlgorithm = "E2E_ICV_ALGORITHM"
	EvE2EDataTransfer = "E2E_DATA_TRANSFER_ABORT"
	EvE2ERekey        = "E2E_REKEY"
)

func init() {
	for k, v := range map[string]string{EvE2EAssociated: "notice", EvE2EHandshake: "warning", EvE2ESignature: "alarm",
		EvE2EReplay: "alarm", EvE2EICV: "alarm", EvE2EICVAlgorithm: "alarm", EvE2EDataTransfer: "warning", EvE2ERekey: "notice"} {
		authSeverity[k] = v
	}
}

// E2E window of 13.3.1.1 and 14.3.4 f, 14.4.3 a.
const E2EWindow = 10 * time.Minute

// E2EOptions configure E2E security for an MMS client or server: the ICV
// algorithms in order of preference (hmac-sha3-256, kmac256; default
// both), the encryption (none, aes128-cbc, aes256-cbc, aes256-gcm), the
// Diffie-Hellman group (23, P-256, the default, or 14, MODP 2048) and the
// key renewal interval (15m to 24h, default 1h). A server with
// RequireEncryption refuses associations without encryption, one with
// encryption "none" refuses encryption.
type E2EOptions struct {
	ICV               []string
	Encryption        string
	RequireEncryption bool
	DHGroup           int
	// RekeyInterval as a Go duration ("1h"); empty for the default.
	RekeyInterval string
}

// E2E is a built E2E security configuration.
type E2E struct {
	auth       *CertAuth
	icv        []string // OIDs by preference
	enc        string   // encryption OID, "" for none
	requireEnc bool
	group      int
	rekey      time.Duration
	nextID     atomic.Uint32

	mu   sync.Mutex
	seen map[string]time.Time // handshake time + association ID
}

var icvNames = map[string]string{"hmac-sha3-256": oidHMACSHA3_256, "kmac256": oidKMACSHAKE256}
var encNames = map[string]string{"none": "", "": "", "aes128-cbc": oidAES128CBC, "aes256-cbc": oidAES256CBC, "aes256-gcm": oidAES256GCM}

// Auth is the ACSE identity E2E security signs with.
func (e *E2E) Auth() *CertAuth { return e.auth }

// NewE2E checks the options and uses auth's identity (certificate, key and
// peer check; an RSA key of 2048 bits or more) for the E2E signatures.
func NewE2E(auth *CertAuth, o E2EOptions) (*E2E, error) {
	if auth == nil {
		return nil, errors.New("e2e: no identity")
	}
	s := &o
	e := &E2E{auth: auth, group: s.DHGroup, requireEnc: s.RequireEncryption, rekey: time.Hour, seen: map[string]time.Time{}}
	names := s.ICV
	if len(names) == 0 {
		names = []string{"hmac-sha3-256", "kmac256"}
	}
	for _, n := range names {
		oid, ok := icvNames[n]
		if !ok {
			return nil, fmt.Errorf("e2e: icv %q is not hmac-sha3-256 or kmac256", n)
		}
		e.icv = append(e.icv, oid)
	}
	enc, ok := encNames[s.Encryption]
	if !ok {
		return nil, fmt.Errorf("e2e: encryption %q is not none, aes128-cbc, aes256-cbc or aes256-gcm", s.Encryption)
	}
	e.enc = enc
	if e.requireEnc && enc == "" {
		return nil, errors.New("e2e: requireEncryption needs an encryption")
	}
	switch e.group {
	case 0:
		e.group = 23
	case 14, 23:
	default:
		return nil, fmt.Errorf("e2e: dhGroup %d is not 23 (P-256) or 14 (MODP 2048)", e.group)
	}
	if s.RekeyInterval != "" {
		d, err := time.ParseDuration(s.RekeyInterval)
		if err != nil || d < 15*time.Minute || d > 24*time.Hour {
			return nil, fmt.Errorf("e2e: rekeyInterval %q must be 15m to 24h (13.3.2)", s.RekeyInterval)
		}
		e.rekey = d
	}
	return e, nil
}

// E2EError is a failed E2E check: a diagnostic, or an alarm (no
// diagnostic is sent).
type E2EError struct {
	Diag   int
	Alarm  string // event mnemonic when an alarm event was raised
	Reason string
	// Handshake marks a handshake diagnostic (else a data transfer one).
	Handshake bool
}

// Error describes the failure.
func (e *E2EError) Error() string {
	if e.Alarm != "" {
		return "IEC 62351-4 E2E: " + e.Reason + " (alarm " + e.Alarm + ")"
	}
	kind := "data transfer"
	if e.Handshake {
		kind = "handshake"
	}
	return fmt.Sprintf("IEC 62351-4 E2E: %s (%s diagnostic %d)", e.Reason, kind, e.Diag)
}

func hsErr(diag int, f string, a ...any) *E2EError {
	return &E2EError{Diag: diag, Reason: fmt.Sprintf(f, a...), Handshake: true}
}
func dtErr(diag int, f string, a ...any) *E2EError {
	return &E2EError{Diag: diag, Reason: fmt.Sprintf(f, a...)}
}
func alarm(ev string, handshake bool, f string, a ...any) *E2EError {
	return &E2EError{Alarm: ev, Reason: fmt.Sprintf(f, a...), Handshake: handshake}
}

// ---- encoding helpers ---------------------------------------------------------

func algID(oid string, null bool) []byte {
	if null {
		return T(0x30, T(0x06, OID(oid)), []byte{0x05, 0x00})
	}
	return T(0x30, T(0x06, OID(oid)))
}

// namedBits encodes a BIT STRING of named bits (trailing zero bits
// removed).
func namedBits(bits ...bool) []byte {
	last := -1
	for i, b := range bits {
		if b {
			last = i
		}
	}
	if last < 0 {
		return T(0x03, []byte{0})
	}
	n := last/8 + 1
	v := make([]byte, n+1)
	v[0] = byte(n*8 - (last + 1))
	for i := 0; i <= last; i++ {
		if bits[i] {
			v[1+i/8] |= 0x80 >> (i % 8)
		}
	}
	return T(0x03, v)
}

func bitSet(e Elem, i int) bool {
	if len(e.Val) < 1+i/8+1 {
		return false
	}
	return e.Val[1+i/8]&(0x80>>(i%8)) != 0
}

func algOID(e Elem) string {
	kids, err := e.Children()
	if err != nil || len(kids) == 0 || kids[0].Tag != 0x06 {
		return ""
	}
	return DecodeOID(kids[0].Val)
}

func e2eTime(t time.Time) []byte { return authTime(t) }

// rawOf re-encodes an element (definite, minimal length: what our peers
// and we send).
func rawOf(e Elem) []byte { return T(e.Tag, e.Val) }

func bgCtx() context.Context { return context.Background() }

// e2eExternal wraps a SecPDU as ACSE user information (OSI-AssoReq and
// its siblings: EXTERNAL with the indirect reference and [0] EXPLICIT).
func e2eExternal(pci int, sec []byte) []byte {
	return T(0xbe, T(0x28, Int(0x02, int64(pci)), T(0xa0, sec)))
}

// e2eFromExternal returns the SecPDU of ACSE user information.
func e2eFromExternal(ui Elem) (int, Elem, error) {
	ext, _, err := Parse(ui.Val)
	if err != nil {
		return 0, Elem{}, err
	}
	kids, err := ext.Children()
	if err != nil {
		return 0, Elem{}, err
	}
	pci := 0
	for _, k := range kids {
		switch k.Tag {
		case 0x02:
			v, _ := DecodeInt(k.Val)
			pci = int(v)
		case 0xa0:
			in, _, err := Parse(k.Val)
			return pci, in, err
		}
	}
	return 0, Elem{}, errors.New("e2e: no single-ASN1-type in the user information")
}

// applData is Virtual-API ApplData: [UNIVERSAL 8] IMPLICIT SEQUENCE
// {indirect-Reference, [0] MMSpdu}.
func applData(pciMMS int, pdu []byte) []byte {
	return T(0x28, Int(0x02, int64(pciMMS)), T(0xa0, pdu))
}

func applDataPDU(e Elem) ([]byte, error) {
	if e.Tag != 0x28 {
		return nil, fmt.Errorf("ApplData with tag %#x", e.Tag)
	}
	kids, err := e.Children()
	if err != nil {
		return nil, err
	}
	for _, k := range kids {
		if k.Tag == 0xa0 {
			return k.Val, nil
		}
	}
	return nil, errors.New("ApplData without the MMS PDU")
}

// ---- keys ---------------------------------------------------------------------

type dhKey struct {
	ec  *ecdh.PrivateKey
	mod *modpDH
}

func newDHKey(group int) (*dhKey, error) {
	if group == 14 {
		m, err := newModP14()
		return &dhKey{mod: m}, err
	}
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	return &dhKey{ec: k}, err
}

func (k *dhKey) public() []byte {
	if k.mod != nil {
		return k.mod.Public()
	}
	return k.ec.PublicKey().Bytes()
}

func (k *dhKey) shared(peer []byte) ([]byte, error) {
	if k.mod != nil {
		return k.mod.Shared(peer)
	}
	p, err := ecdh.P256().NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	return k.ec.ECDH(p)
}

// keyset is one direction pair of keys.
type keyset struct {
	icvC, icvS, encC, encS []byte
}

func encKeyLen(enc string) int {
	switch enc {
	case oidAES128CBC:
		return 16
	case oidAES256CBC, oidAES256GCM:
		return 32
	}
	return 0
}

// deriveKeys is 13.3.1.3: HKDF-SHA256 with the salt and the DH secret.
func deriveKeys(z, salt []byte, enc string) (keyset, error) {
	var ks keyset
	switch {
	case enc == oidAES256GCM:
		okm, err := hkdf.Key(sha256.New, z, salt, "", 64)
		if err != nil {
			return ks, err
		}
		ks.encC, ks.encS = okm[:32], okm[32:]
	case enc == "":
		okm, err := hkdf.Key(sha256.New, z, salt, "", 64)
		if err != nil {
			return ks, err
		}
		ks.icvC, ks.icvS = okm[:32], okm[32:]
	default:
		n := encKeyLen(enc)
		okm, err := hkdf.Key(sha256.New, z, salt, "", 64+2*n)
		if err != nil {
			return ks, err
		}
		ks.icvC, ks.icvS, ks.encC, ks.encS = okm[:32], okm[32:64], okm[64:64+n], okm[64+n:]
	}
	return ks, nil
}

func saltStep(data, prev []byte) []byte {
	h := sha256.New()
	h.Write(data)
	h.Write(prev)
	return h.Sum(nil)
}

func icvHash(alg string, key []byte) hash.Hash {
	switch alg {
	case oidKMACSHAKE256:
		return kmac.New256(key, 64, nil) // RFC 8702 defaults: 512 bits, empty customization
	default:
		return hmac.New(func() hash.Hash { return sha3.New256() }, key)
	}
}

func computeICV(alg string, key, data []byte) []byte {
	h := icvHash(alg, key)
	h.Write(data)
	return h.Sum(nil)
}

// ---- signatures ---------------------------------------------------------------

func (e *E2E) sign(tbsContent []byte) ([]byte, error) {
	h := sha256.Sum256(tbsContent)
	e.auth.mu.Lock()
	key := e.auth.key
	e.auth.mu.Unlock()
	sig, err := key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return T(0x30, algID(oidRSAEncryption, true), T(0x04, sig)), nil
}

func (e *E2E) cert() []byte {
	e.auth.mu.Lock()
	defer e.auth.mu.Unlock()
	return e.auth.chain[0].Raw
}

func verifySig(cert *x509.Certificate, tbsContent []byte, sigElem Elem) error {
	kids, err := sigElem.Children()
	if err != nil || len(kids) < 2 || kids[1].Tag != 0x04 {
		return errors.New("a malformed Signature")
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("the certificate has no RSA key")
	}
	h := sha256.Sum256(tbsContent)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], kids[1].Val)
}

// token3 builds a ClearToken3.
func (e *E2E) token3(assoID string) []byte {
	parts := [][]byte{algID(oidRSAEncryption, true)}
	if assoID != "" {
		parts = append(parts, Str(0x0c, assoID))
	}
	parts = append(parts, T(0x18, e2eTime(e.auth.now())), T(0x04, e.cert()))
	return T(0x30, parts...)
}

// signed builds SEQUENCE {tbs SEQUENCE {parts}, sign} with the given
// outer tag.
func (e *E2E) signed(tag byte, parts ...[]byte) ([]byte, error) {
	content := bytes.Join(parts, nil)
	tbs := T(0x30, content)
	sig, err := e.sign(content)
	if err != nil {
		return nil, err
	}
	return T(tag, tbs, sig), nil
}

// secReject builds a HandshakeSecReject (or HandshakeSecAbort, DtSecAbort)
// SecPDU with the outer tag of its CHOICE alternative; diag < 0 leaves
// the diagnostic out (after an alarm).
func (e *E2E) secAbort(tag byte, assoID string, diag int) []byte {
	parts := [][]byte{e.token3(assoID)}
	if diag >= 0 {
		parts = append(parts, Int(0x0a, int64(diag)))
	}
	b, _ := e.signed(tag, parts...)
	return b
}

func errDiag(err error) int {
	var ee *E2EError
	if errors.As(err, &ee) && ee.Alarm == "" {
		return ee.Diag
	}
	if errors.As(err, &ee) {
		return -1
	}
	return HDProtocolError
}

// ---- handshake ----------------------------------------------------------------

// token1 fields decoded.
type token1 struct {
	sigAlg     string
	cert       *x509.Certificate
	version    Elem
	assoID     string
	group      int
	pub        []byte
	hmac       string
	time       time.Time
	aea        bool
	encAlgs    []string
	icvAlgs    []string
	confApplEn bool
}

// verifySigned checks the certificate and the signature of a signed
// SecPDU (14.3.2: before anything signed is used) and returns the tbs
// fields, the tbs contents and the certificate.
func (e *E2E) verifySigned(pdu Elem, peer string, handshake bool) ([]Elem, []byte, *x509.Certificate, *E2EError) {
	kids, err := pdu.Children()
	if err != nil || len(kids) < 2 {
		return nil, nil, nil, hsErr(HDProtocolError, "a malformed SecPDU")
	}
	var tbs, sig Elem
	for i, k := range kids {
		if k.Tag == 0x30 && i+1 < len(kids) && kids[i+1].Tag == 0x30 {
			tbs, sig = k, kids[i+1]
			break
		}
	}
	fields, err := tbs.Children()
	if err != nil || len(fields) == 0 || fields[0].Tag != 0x30 {
		return nil, nil, nil, hsErr(HDProtocolError, "a SecPDU without a token")
	}
	tok, err := fields[0].Children()
	if err != nil || len(tok) < 2 {
		return nil, nil, nil, hsErr(HDProtocolError, "a malformed token")
	}
	sigAlg := algOID(tok[0])
	var certDER []byte
	for _, f := range tok {
		if f.Tag == 0x04 && certDER == nil {
			certDER = f.Val
		}
	}
	sigKids, _ := sig.Children()
	if len(sigKids) == 0 || algOID(sigKids[0]) != sigAlg {
		return nil, nil, nil, alarm(EvE2ESignature, handshake, "the signature algorithm differs from sigAlg (14.3.2 a)")
	}
	if sigAlg != oidRSAEncryption && sigAlg != oidSHA256RSA {
		return nil, nil, nil, hsErr(HDInvalidSignatureAlg, "signature algorithm %s is not supported", sigAlg)
	}
	if len(certDER) > MaxAuthCertificate {
		return nil, nil, nil, hsErr(HDInvalidCertificate, "the certificate is %d octets", len(certDER))
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, hsErr(HDInvalidCertificate, "the certificate does not parse: %v", err)
	}
	if pub, ok := cert.PublicKey.(*rsa.PublicKey); !ok || pub.N.BitLen() < 2048 {
		return nil, nil, nil, hsErr(HDInvalidCertificate, "the certificate needs an RSA key of 2048 bits or more")
	}
	if err := verifySig(cert, tbs.Val, sig); err != nil {
		e.auth.event(EvE2ESignature, peer, map[string]string{"clause": "IEC 62351-4 14.3.2", "certificate": cert.Subject.String(), "method": "e2e"})
		return nil, nil, nil, alarm(EvE2ESignature, handshake, "the signature does not verify")
	}
	if err := e.auth.id.VerifyPeer(bgCtx(), []*x509.Certificate{cert}, peer); err != nil {
		return nil, nil, nil, hsErr(HDInvalidCertPath, "the certificate path: %v", err)
	}
	return fields, tbs.Val, cert, nil
}

func parseToken1(el Elem) (token1, *E2EError) {
	var t token1
	f, err := el.Children()
	if err != nil {
		return t, hsErr(HDProtocolError, "ClearToken1: %v", err)
	}
	for _, x := range f {
		switch x.Tag {
		case 0x30:
			switch {
			case t.sigAlg == "":
				t.sigAlg = algOID(x)
			case t.group == 0 && len(x.Val) > 0 && x.Val[0] == 0x02:
				dh, _ := x.Children()
				if len(dh) >= 2 {
					g, _ := DecodeInt(dh[0].Val)
					t.group, t.pub = int(g), dh[1].Val
				}
			case t.hmac == "":
				t.hmac = algOID(x)
			default: // encr-mode aea
				t.aea = true
				algs, _ := x.Children()
				for _, a := range algs {
					t.encAlgs = append(t.encAlgs, algOID(a))
				}
			}
		case 0x04:
			if t.cert == nil {
				t.cert, _ = x509.ParseCertificate(x.Val)
			}
		case 0x03:
			if t.version.Tag == 0 {
				t.version = x
			} else {
				t.confApplEn = bitSet(x, 1)
			}
		case 0x0c:
			t.assoID = string(x.Val)
		case 0x18:
			tm, err := parseAuthTime(x.Val)
			if err != nil {
				return t, hsErr(HDInvalidTime, "time %q", x.Val)
			}
			t.time = tm
		case 0xa0: // non-aea
			parts, _ := x.Children()
			for _, p := range parts {
				algs, _ := p.Children()
				for _, a := range algs {
					switch p.Tag {
					case 0xa0:
						t.encAlgs = append(t.encAlgs, algOID(a))
					case 0xa1:
						t.icvAlgs = append(t.icvAlgs, algOID(a))
					}
				}
			}
		}
	}
	if t.sigAlg == "" || t.assoID == "" || t.group == 0 || t.hmac == "" || t.time.IsZero() || (!t.aea && len(t.icvAlgs) == 0) {
		return t, hsErr(HDProtocolError, "ClearToken1 lacks a mandatory component")
	}
	return t, nil
}

func (e *E2E) encrMode(aea bool, encs, icvs []string) []byte {
	if aea {
		var algs [][]byte
		for _, a := range encs {
			algs = append(algs, algID(a, false))
		}
		return T(0x30, algs...)
	}
	var parts [][]byte
	if len(encs) > 0 {
		var algs [][]byte
		for _, a := range encs {
			algs = append(algs, algID(a, false))
		}
		parts = append(parts, T(0xa0, algs...))
	}
	var algs [][]byte
	for _, a := range icvs {
		algs = append(algs, algID(a, false))
	}
	parts = append(parts, T(0xa1, algs...))
	return T(0xa0, parts...)
}

func (e *E2E) token1(assoID string, pub []byte, aea bool, encs, icvs []string, tls bool) []byte {
	return T(0x30,
		algID(oidRSAEncryption, true),
		T(0x04, e.cert()),
		namedBits(true), // version v1
		Str(0x0c, assoID),
		T(0x30, Int(0x02, int64(e.group)), T(0x04, pub)),
		algID(oidHMACSHA256, true),
		T(0x18, e2eTime(e.auth.now())),
		e.encrMode(aea, encs, icvs),
		namedBits(tls, len(encs) > 0))
}

// checkTime is 14.3.4 f and g.
func (e *E2E) checkHandshakeTime(t time.Time, assoID string, peer string) *E2EError {
	now := e.auth.now()
	if d := now.Sub(t); d > E2EWindow || d < -E2EWindow {
		return hsErr(HDInvalidTime, "the time %s is more than 10 minutes from ours", t.UTC().Format(time.RFC3339))
	}
	key := t.UTC().Format(time.RFC3339Nano) + "|" + assoID
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, at := range e.seen {
		if now.Sub(at) > E2EWindow {
			delete(e.seen, k)
		}
	}
	if _, dup := e.seen[key]; dup {
		e.auth.event(EvE2EReplay, peer, map[string]string{"clause": "IEC 62351-4 14.3.4 g", "association": assoID, "method": "e2e"})
		return alarm(EvE2EReplay, true, "the handshake time and association ID were seen before")
	}
	e.seen[key] = now
	return nil
}

// e2eClientHS is a handshake the client started.
type e2eClientHS struct {
	e              *E2E
	assoID         string
	dh             *dhKey
	aea            bool
	encs, icvs     []string
	tbs            []byte
	pciMMS, pciE2E int
}

// clientHello builds the HandshakeReq around an initiate request.
func (e *E2E) clientHello(initiate []byte, pciMMS, pciE2E int, tls bool) (*e2eClientHS, []byte, error) {
	dh, err := newDHKey(e.group)
	if err != nil {
		return nil, nil, err
	}
	hs := &e2eClientHS{e: e, assoID: strconv.Itoa(int(e.nextID.Add(1) % 1000)), dh: dh, icvs: e.icv, pciMMS: pciMMS, pciE2E: pciE2E}
	if e.enc == oidAES256GCM {
		hs.aea, hs.encs, hs.icvs = true, []string{oidAES256GCM}, nil
	} else if e.enc != "" {
		hs.encs = []string{e.enc}
	}
	tok := e.token1(hs.assoID, dh.public(), hs.aea, hs.encs, hs.icvs, tls)
	ad := applData(pciMMS, initiate)
	hs.tbs = append(append([]byte{}, tok...), ad...)
	sig, err := e.sign(hs.tbs)
	if err != nil {
		return nil, nil, err
	}
	return hs, T(0x30, Str(0x0c, E2EProtocol), T(0x30, tok, ad), sig), nil
}

// finish checks the HandshakeRsp and returns the initiate response and
// the session; an error is an *E2EError to answer with HandshakeSecAbort.
func (hs *e2eClientHS) finish(rsp Elem, peer string, tls bool) ([]byte, *e2eSession, error) {
	e := hs.e
	switch rsp.Tag {
	case 0xa1: // assoAccept
	case 0xa2, 0xa3:
		fields, _, _, verr := e.verifySigned(rsp, peer, true)
		why := "the server refused the association"
		if verr == nil && rsp.Tag == 0xa3 && len(fields) > 1 && fields[1].Tag == 0x0a {
			d, _ := DecodeInt(fields[1].Val)
			why = fmt.Sprintf("the server refused the E2E handshake (diagnostic %d)", d)
		}
		return nil, nil, fmt.Errorf("%w: %s", ErrRejected, why)
	default:
		return nil, nil, hsErr(HDProtocolError, "HandshakeRsp alternative %#x", rsp.Tag)
	}
	fields, tbs, cert, verr := e.verifySigned(rsp, peer, true)
	if verr != nil {
		return nil, nil, verr
	}
	t, terr := parseToken1(fields[0])
	if terr != nil {
		return nil, nil, terr
	}
	if !bitSet(t.version, 0) || len(t.version.Val) > 2 {
		return nil, nil, hsErr(HDUnexpectedVersion, "the server did not select version 1")
	}
	if err := e.checkHandshakeTime(t.time, t.assoID, peer); err != nil {
		return nil, nil, err
	}
	if !strings.HasPrefix(t.assoID, hs.assoID+":") {
		return nil, nil, hsErr(HDProtocolError, "association ID %q does not extend ours %q", t.assoID, hs.assoID)
	}
	if t.group != e.group {
		return nil, nil, hsErr(HDIllegalDHGroup, "the server selected DH group %d", t.group)
	}
	if t.hmac != oidHMACSHA256 {
		return nil, nil, hsErr(HDHMACNotSupported, "the server selected HMAC %s", t.hmac)
	}
	var enc, icv string
	switch {
	case hs.aea && !t.aea:
		return nil, nil, hsErr(HDProtocolError, "the server left authenticated encryption")
	case !hs.aea && t.aea:
		return nil, nil, hsErr(HDAENotUsed, "the server selected authenticated encryption")
	case hs.aea:
		if len(t.encAlgs) != 1 {
			return nil, nil, hsErr(HDSingleAERequired, "the server selected %d AE algorithms", len(t.encAlgs))
		}
		if t.encAlgs[0] != oidAES256GCM {
			return nil, nil, hsErr(HDInvalidAEAlgorithm, "AE algorithm %s was not proposed", t.encAlgs[0])
		}
		enc = oidAES256GCM
	default:
		if len(hs.encs) > 0 {
			if len(t.encAlgs) != 1 {
				return nil, nil, hsErr(HDSingleEncryptRequired, "the server selected %d encryption algorithms", len(t.encAlgs))
			}
			if !contains(hs.encs, t.encAlgs[0]) {
				return nil, nil, hsErr(HDInvalidEncryptionAlg, "encryption %s was not proposed", t.encAlgs[0])
			}
			enc = t.encAlgs[0]
		} else if len(t.encAlgs) > 0 {
			return nil, nil, hsErr(HDProtocolError, "the server selected encryption that was not proposed")
		}
		if len(t.icvAlgs) != 1 {
			return nil, nil, hsErr(HDSingleICVRequired, "the server selected %d ICV algorithms", len(t.icvAlgs))
		}
		if !contains(hs.icvs, t.icvAlgs[0]) {
			return nil, nil, hsErr(HDICVNotSupported, "ICV algorithm %s was not proposed", t.icvAlgs[0])
		}
		icv = t.icvAlgs[0]
	}
	if len(fields) < 2 {
		return nil, nil, hsErr(HDProtocolError, "HandshakeAcc without ApplData")
	}
	initResp, err := applDataPDU(fields[1])
	if err != nil {
		return nil, nil, hsErr(HDProtocolError, "%v", err)
	}
	z, err := hs.dh.shared(t.pub)
	if err != nil {
		return nil, nil, hsErr(HDProtocolError, "the server's DH public key: %v", err)
	}
	salt := saltStep(tbs, saltStep(hs.tbs, make([]byte, 32)))
	keys, err := deriveKeys(z, salt, enc)
	if err != nil {
		return nil, nil, err
	}
	s := &e2eSession{e: e, client: true, assoID: t.assoID, pciMMS: hs.pciMMS, pciE2E: hs.pciE2E, icvAlg: icv, enc: enc,
		send: keys, recv: keys, salt: salt, peerPub: t.pub, keyAt: e.auth.now(), peerCert: cert, peer: peer}
	e.auth.event(EvE2EAssociated, peer, map[string]string{"clause": "IEC 62351-4 13.1", "association": t.assoID, "certificate": cert.Subject.String(),
		"icv": icv, "encryption": enc, "method": "e2e"})
	return initResp, s, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// e2eServerHS is a checked HandshakeReq.
type e2eServerHS struct {
	e              *E2E
	t              token1
	tbs            []byte
	cert           *x509.Certificate
	initiate       []byte
	aea            bool
	enc, icv       string
	assoID         string
	pciMMS, pciE2E int
	peer           string
}

// serverCheck checks a HandshakeReq (14.3); an error is an *E2EError to
// answer with HandshakeSecReject.
func (e *E2E) serverCheck(req Elem, pciMMS, pciE2E int, peer string) (*e2eServerHS, error) {
	kids, err := req.Children()
	if err != nil || len(kids) < 3 || kids[0].Tag != 0x0c {
		return nil, hsErr(HDProtocolError, "a malformed HandshakeReq")
	}
	inner := T(0x30, rawOf(kids[1]), rawOf(kids[2]))
	ie, _, _ := Parse(inner)
	fields, tbs, cert, verr := e.verifySigned(ie, peer, true)
	if verr != nil {
		return nil, verr
	}
	if string(kids[0].Val) != E2EProtocol {
		return nil, hsErr(HDProtectedNotSupported, "protected protocol %q", kids[0].Val)
	}
	t, terr := parseToken1(fields[0])
	if terr != nil {
		return nil, terr
	}
	if !bitSet(t.version, 0) {
		return nil, hsErr(HDUnexpectedVersion, "version 1 is not proposed")
	}
	if err := e.checkHandshakeTime(t.time, t.assoID, peer); err != nil {
		return nil, err
	}
	if len(t.assoID) < 1 || len(t.assoID) > 3 || strings.Trim(t.assoID, "0123456789") != "" {
		return nil, hsErr(HDProtocolError, "association ID %q is not one to three digits", t.assoID)
	}
	if t.group != 14 && t.group != 23 {
		return nil, hsErr(HDDHGroupNotSupported, "DH group %d", t.group)
	}
	if t.hmac != oidHMACSHA256 {
		return nil, hsErr(HDHMACNotSupported, "HMAC %s", t.hmac)
	}
	hs := &e2eServerHS{e: e, t: t, tbs: tbs, cert: cert, pciMMS: pciMMS, pciE2E: pciE2E, peer: peer}
	wantEnc := len(t.encAlgs) > 0
	switch {
	case t.aea && e.enc == "":
		return nil, hsErr(HDAEASelectButEncNotSupp, "authenticated encryption proposed, encryption is off here")
	case t.aea && e.enc != oidAES256GCM:
		return nil, hsErr(HDEncrModeAEANotSupp, "authenticated encryption is not used here")
	case t.aea:
		if !contains(t.encAlgs, oidAES256GCM) {
			return nil, hsErr(HDAEANotSupported, "none of the proposed AE algorithms is supported")
		}
		hs.aea, hs.enc = true, oidAES256GCM
	default:
		if e.enc == oidAES256GCM {
			return nil, hsErr(HDAEIsRequired, "authenticated encryption is required here")
		}
		if wantEnc && e.enc == "" && !e.requireEnc {
			return nil, hsErr(HDEncryptionNotRequired, "encryption is not used here")
		}
		if wantEnc {
			for _, a := range t.encAlgs {
				if encKeyLen(a) > 0 && a != oidAES256GCM {
					hs.enc = a
					break
				}
			}
			if hs.enc == "" {
				return nil, hsErr(HDEncryptNotSupported, "none of the proposed encryption algorithms is supported")
			}
		}
		for _, a := range t.icvAlgs {
			if contains(e.icv, a) {
				hs.icv = a
				break
			}
		}
		if hs.icv == "" {
			return nil, hsErr(HDICVNotSupported, "none of the proposed ICV algorithms is supported")
		}
	}
	if t.confApplEn != (hs.enc != "") {
		return nil, hsErr(HDProtocolError, "confParams applProtected does not match the encryption proposed")
	}
	if e.requireEnc && hs.enc == "" {
		return nil, hsErr(HDEncryptionRequired, "encryption is required here")
	}
	if len(fields) < 2 {
		return nil, hsErr(HDProtocolError, "HandshakeReq without ApplData")
	}
	if hs.initiate, err = applDataPDU(fields[1]); err != nil {
		return nil, hsErr(HDProtocolError, "%v", err)
	}
	return hs, nil
}

// accept builds the HandshakeAcc ([1] of HandshakeRsp) and the session.
func (hs *e2eServerHS) accept(initResp []byte, tls bool) ([]byte, *e2eSession, error) {
	e := hs.e
	dh, err := newDHKey(hs.t.group)
	if err != nil {
		return nil, nil, err
	}
	z, err := dh.shared(hs.t.pub)
	if err != nil {
		return nil, nil, hsErr(HDProtocolError, "the client's DH public key: %v", err)
	}
	hs.assoID = fmt.Sprintf("%s:%d", hs.t.assoID, e.nextID.Add(1)%1000)
	var encs, icvs []string
	if hs.enc != "" {
		encs = []string{hs.enc}
	}
	if !hs.aea {
		icvs = []string{hs.icv}
	}
	grp := e.group
	e.group = hs.t.group
	tok := e.token1(hs.assoID, dh.public(), hs.aea, encs, icvs, tls)
	e.group = grp
	ad := applData(hs.pciMMS, initResp)
	tbs := append(append([]byte{}, tok...), ad...)
	sig, err := e.sign(tbs)
	if err != nil {
		return nil, nil, err
	}
	salt := saltStep(tbs, saltStep(hs.tbs, make([]byte, 32)))
	keys, err := deriveKeys(z, salt, hs.enc)
	if err != nil {
		return nil, nil, err
	}
	s := &e2eSession{e: e, assoID: hs.assoID, pciMMS: hs.pciMMS, pciE2E: hs.pciE2E, icvAlg: hs.icv, enc: hs.enc,
		send: keys, recv: keys, salt: salt, dh: dh, keyAt: e.auth.now(), peerCert: hs.cert, peer: hs.peer}
	e.auth.event(EvE2EAssociated, hs.peer, map[string]string{"clause": "IEC 62351-4 13.1", "association": hs.assoID,
		"certificate": hs.cert.Subject.String(), "icv": hs.icv, "encryption": hs.enc, "method": "e2e"})
	return T(0xa1, T(0x30, tok, ad), sig), s, nil
}

// reject builds a HandshakeSecReject ([3] of HandshakeRsp).
func (e *E2E) reject(assoID string, err error) []byte {
	return e.secAbort(0xa3, assoID, errDiag(err))
}

// ---- data transfer ------------------------------------------------------------

// e2eSession is an association's E2E state.
type e2eSession struct {
	e              *E2E
	client         bool
	assoID         string
	pciMMS, pciE2E int
	icvAlg, enc    string
	salt           []byte
	peerCert       *x509.Certificate
	peer           string

	mu       sync.Mutex
	send     keyset
	recv     keyset
	sendTime string
	sendSeq  int64
	recvTime string
	recvSeq  int64
	recvAny  bool
	keyAt    time.Time

	// client: the server's retained DH public key, a sent rekey waiting
	// for changedKey and the keys to receive with after it.
	peerPub     []byte
	rekeyWait   bool
	pendingRecv *keyset
	// server: its retained DH key, and keys to send with after the next
	// PDU (which carries changedKey).
	dh          *dhKey
	pendingSend *keyset
	reqRekey    bool
}

func (s *e2eSession) myICV(k keyset) []byte {
	if s.client {
		return k.icvC
	}
	return k.icvS
}
func (s *e2eSession) peerICV(k keyset) []byte {
	if s.client {
		return k.icvS
	}
	return k.icvC
}
func (s *e2eSession) myEnc(k keyset) []byte {
	if s.client {
		return k.encC
	}
	return k.encS
}
func (s *e2eSession) peerEnc(k keyset) []byte {
	if s.client {
		return k.encS
	}
	return k.encC
}

// forceRekey makes the next client PDU renew the keys (tests, reqRekey).
func (s *e2eSession) forceRekey() {
	s.mu.Lock()
	s.keyAt = time.Time{}
	s.mu.Unlock()
}

func pkcs7(b []byte) []byte {
	n := aes.BlockSize - len(b)%aes.BlockSize
	return append(b, bytes.Repeat([]byte{byte(n)}, n)...)
}

func unpkcs7(b []byte) ([]byte, bool) {
	if len(b) == 0 || len(b)%aes.BlockSize != 0 {
		return nil, false
	}
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return nil, false
	}
	for _, x := range b[len(b)-n:] {
		if int(x) != n {
			return nil, false
		}
	}
	return b[:len(b)-n], true
}

// wrap protects an MMS PDU as a DataTransfer value.
func (s *e2eSession) wrap(pdu []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.e.auth.now()
	tm := string(e2eTime(now))
	if tm == s.sendTime {
		s.sendSeq++
	} else {
		s.sendTime, s.sendSeq = tm, 0
	}
	keys := s.send
	var rekeyPub []byte
	var newDH *dhKey
	if s.client && !s.rekeyWait && (s.reqRekey || now.Sub(s.keyAt) >= s.e.rekey) {
		k, err := newDHKey(s.e.group)
		if err != nil {
			return nil, err
		}
		newDH, rekeyPub = k, k.public()
	}
	changed := false
	if !s.client && s.pendingSend != nil {
		changed = true
	}
	ad := applData(s.pciMMS, pdu)
	var iv []byte
	switch s.enc {
	case oidAES256GCM:
		iv = make([]byte, 12)
	case oidAES128CBC, oidAES256CBC:
		iv = make([]byte, 16)
	}
	if iv != nil {
		if _, err := rand.Read(iv); err != nil {
			return nil, err
		}
	}
	ct2parts := [][]byte{Str(0x0c, s.assoID), T(0x18, []byte(tm)), Int(0x02, s.sendSeq)}
	if iv != nil {
		ct2parts = append(ct2parts, T(0x80, iv))
	}
	if rekeyPub != nil {
		ct2parts = append(ct2parts, T(0x81, rekeyPub))
	}
	if changed {
		ct2parts = append(ct2parts, Bool(0x83, true))
	}
	ct2 := T(0x30, ct2parts...)
	var out []byte
	var tbpContent []byte
	switch s.enc {
	case "":
		tbpContent = append(append([]byte{}, ct2...), ad...)
		out = T(0xa0, T(0x30, tbpContent), s.authenticator(keys, tbpContent))
	case oidAES256GCM:
		blk, _ := aes.NewCipher(s.myEnc(keys))
		g, _ := cipher.NewGCM(blk)
		ct := g.Seal(nil, iv, ad, ct2)
		tbpContent = append(append([]byte{}, ct2...), T(0x04, ct)...)
		out = T(0xa1, T(0x30, tbpContent))
	default:
		blk, _ := aes.NewCipher(s.myEnc(keys))
		pt := pkcs7(append([]byte{}, ad...))
		ct := make([]byte, len(pt))
		cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, pt)
		tbpContent = append(append([]byte{}, ct2...), T(0x04, ct)...)
		out = T(0xa1, T(0x30, tbpContent), s.authenticator(keys, tbpContent))
	}
	if newDH != nil {
		// The new keys protect the client's following PDUs; the server's
		// are read with the old ones until its changedKey.
		z, err := newDH.shared(s.peerPub)
		if err != nil {
			return nil, err
		}
		salt := saltStep(tbpContent, s.salt)
		nk, err := deriveKeys(z, salt, s.enc)
		if err != nil {
			return nil, err
		}
		s.salt, s.send, s.pendingRecv, s.rekeyWait, s.keyAt, s.reqRekey = salt, nk, &nk, true, now, false
		s.e.auth.event(EvE2ERekey, s.peer, map[string]string{"clause": "IEC 62351-4 13.3.2", "association": s.assoID, "method": "e2e"})
	}
	if changed {
		s.send, s.pendingSend = *s.pendingSend, nil
	}
	return out, nil
}

func (s *e2eSession) authenticator(keys keyset, tbp []byte) []byte {
	return T(0x30, algID(s.icvAlg, false), T(0x04, computeICV(s.icvAlg, s.myICV(keys), tbp)))
}

// unwrap checks a DataTransfer value and returns the MMS PDU.
func (s *e2eSession) unwrap(b []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dt, _, err := Parse(b)
	if err != nil {
		return nil, dtErr(DDProtocolError, "DataTransfer: %v", err)
	}
	encrypted := dt.Tag == 0xa1
	if dt.Tag != 0xa0 && !encrypted {
		return nil, dtErr(DDProtocolError, "DataTransfer alternative %#x", dt.Tag)
	}
	if encrypted && s.enc == "" {
		return nil, dtErr(DDEncryptionNotSel, "encrypted data, encryption was not selected")
	}
	if !encrypted && s.enc != "" {
		return nil, dtErr(DDEncryptionRequired, "clear data, encryption was selected")
	}
	parts, err := dt.Children()
	if err != nil || len(parts) == 0 || parts[0].Tag != 0x30 {
		return nil, dtErr(DDProtocolError, "a malformed transfer SecPDU")
	}
	tbp := parts[0]
	tf, err := tbp.Children()
	if err != nil || len(tf) < 2 || tf[0].Tag != 0x30 {
		return nil, dtErr(DDProtocolError, "a malformed tbp")
	}
	ct2Raw := rawOf(tf[0])
	c2, err := tf[0].Children()
	if err != nil {
		return nil, dtErr(DDProtocolError, "ClearToken2: %v", err)
	}
	var assoID, tm string
	var seq int64 = -1
	var iv, rekey []byte
	changed, req := false, false
	for _, f := range c2 {
		switch f.Tag {
		case 0x03:
			if !bitSet(f, 0) {
				return nil, dtErr(DDUnexpectedVersion, "a version other than 1")
			}
		case 0x0c:
			assoID = string(f.Val)
		case 0x18:
			tm = string(f.Val)
		case 0x02:
			v, _ := DecodeInt(f.Val)
			seq = v
		case 0x80:
			iv = f.Val
		case 0x81:
			rekey = f.Val
		case 0x82:
			req = len(f.Val) == 1 && f.Val[0] != 0
		case 0x83:
			changed = len(f.Val) == 1 && f.Val[0] != 0
		}
	}
	if assoID != s.assoID || tm == "" || seq < 0 {
		return nil, dtErr(DDProtocolError, "ClearToken2 names association %q or lacks time or sequence", assoID)
	}
	if s.enc != "" && iv == nil {
		return nil, dtErr(DDAESIVRequired, "no IV")
	}
	keys := s.recv
	var ad []byte
	if s.enc == oidAES256GCM {
		if len(iv) != 12 || tf[1].Tag != 0x04 {
			return nil, dtErr(DDProtocolError, "AES-GCM needs a 12-octet nonce and the ciphertext")
		}
		blk, _ := aes.NewCipher(s.peerEnc(keys))
		g, _ := cipher.NewGCM(blk)
		if ad, err = g.Open(nil, iv, tf[1].Val, ct2Raw); err != nil {
			s.e.auth.event(EvE2EICV, s.peer, map[string]string{"clause": "IEC 62351-4 14.4.2 c", "association": s.assoID, "method": "e2e"})
			return nil, alarm(EvE2EICV, false, "the authenticated encryption tag does not verify")
		}
	} else {
		if len(parts) < 2 {
			return nil, dtErr(DDProtocolError, "no Authenticator")
		}
		af, err := parts[1].Children()
		if err != nil || len(af) < 2 {
			return nil, dtErr(DDProtocolError, "a malformed Authenticator")
		}
		var algE, icvE Elem
		for i, f := range af {
			if f.Tag == 0x30 {
				algE = f
				if i+1 < len(af) {
					icvE = af[i+1]
				}
			}
		}
		if algOID(algE) != s.icvAlg {
			s.e.auth.event(EvE2EICVAlgorithm, s.peer, map[string]string{"clause": "IEC 62351-4 14.4.2 a", "association": s.assoID, "method": "e2e"})
			return nil, alarm(EvE2EICVAlgorithm, false, "ICV algorithm %s is not the one agreed", algOID(algE))
		}
		want := computeICV(s.icvAlg, s.peerICV(keys), tbp.Val)
		if icvE.Tag != 0x04 || subtle.ConstantTimeCompare(want, icvE.Val) != 1 {
			s.e.auth.event(EvE2EICV, s.peer, map[string]string{"clause": "IEC 62351-4 14.4.2 c", "association": s.assoID, "method": "e2e"})
			return nil, alarm(EvE2EICV, false, "the ICV does not verify")
		}
		if s.enc != "" {
			if len(iv) != 16 || tf[1].Tag != 0x04 || len(tf[1].Val)%aes.BlockSize != 0 {
				return nil, dtErr(DDAESIVRequired, "AES-CBC needs a 16-octet IV and whole blocks")
			}
			blk, _ := aes.NewCipher(s.peerEnc(keys))
			pt := make([]byte, len(tf[1].Val))
			cipher.NewCBCDecrypter(blk, iv).CryptBlocks(pt, tf[1].Val)
			var ok bool
			if ad, ok = unpkcs7(pt); !ok {
				return nil, dtErr(DDProtocolError, "bad padding")
			}
		} else {
			ad = rawOf(tf[1])
		}
	}
	// 14.4.3: time, replay, sequence.
	t, err := parseAuthTime([]byte(tm))
	if err != nil {
		return nil, dtErr(DDProtocolError, "time %q", tm)
	}
	now := s.e.auth.now()
	if d := now.Sub(t); d > E2EWindow || d < -E2EWindow {
		return nil, dtErr(DDProtocolError, "the time %s is more than 10 minutes from ours", tm)
	}
	if s.recvAny {
		prev, _ := parseAuthTime([]byte(s.recvTime))
		switch {
		case t.Before(prev):
			return nil, dtErr(DDProtocolError, "the time %s is earlier than the preceding PDU's", tm)
		case tm == s.recvTime && seq <= s.recvSeq:
			s.e.auth.event(EvE2EReplay, s.peer, map[string]string{"clause": "IEC 62351-4 14.4.3 c", "association": s.assoID, "method": "e2e"})
			return nil, alarm(EvE2EReplay, false, "time %s and sequence %d were received before", tm, seq)
		case tm == s.recvTime && seq != s.recvSeq+1:
			return nil, dtErr(DDInvalidSequence, "sequence %d after %d", seq, s.recvSeq)
		case tm != s.recvTime && seq != 0:
			return nil, dtErr(DDInvalidSequence, "sequence %d at a new time", seq)
		}
	} else if seq != 0 {
		return nil, dtErr(DDInvalidSequence, "the first sequence number is %d", seq)
	}
	// Key renewal (14.4.3 f to i).
	switch {
	case s.client && rekey != nil:
		return nil, dtErr(DDProtocolError, "a rekey from the server")
	case !s.client && changed:
		return nil, dtErr(DDProtocolError, "changedKey from the client")
	case !s.client && req:
		return nil, dtErr(DDProtocolError, "reqRekey from the client")
	case !s.client && rekey != nil && s.pendingSend != nil:
		return nil, dtErr(DDUnexpectedDHKey, "a second rekey before changedKey")
	case s.client && changed && !s.rekeyWait:
		return nil, dtErr(DDUnexpectedChanged, "changedKey without a rekey")
	}
	pdu, err := applDataPDUBytes(ad)
	if err != nil {
		return nil, dtErr(DDProtocolError, "%v", err)
	}
	s.recvTime, s.recvSeq, s.recvAny = tm, seq, true
	if !s.client && rekey != nil {
		z, err := s.dh.shared(rekey)
		if err != nil {
			return nil, dtErr(DDProtocolError, "rekey: %v", err)
		}
		salt := saltStep(tbp.Val, s.salt)
		nk, err := deriveKeys(z, salt, s.enc)
		if err != nil {
			return nil, err
		}
		s.salt, s.recv, s.pendingSend = salt, nk, &nk
		s.e.auth.event(EvE2ERekey, s.peer, map[string]string{"clause": "IEC 62351-4 13.3.2", "association": s.assoID, "method": "e2e"})
	}
	if s.client && changed {
		s.recv, s.pendingRecv, s.rekeyWait = *s.pendingRecv, nil, false
	}
	if s.client && req {
		s.reqRekey = true
	}
	return pdu, nil
}

func applDataPDUBytes(b []byte) ([]byte, error) {
	e, rest, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("octets after ApplData")
	}
	return applDataPDU(e)
}

// dtAbort is the ABRT user information of a DtSecAbort ([1] of
// AssoAbort).
func (s *e2eSession) dtAbort(err error) []byte {
	return e2eAbrt(s.pciE2E, s.e.secAbort(0xa1, s.assoID, errDiag(err)))
}

// e2eAbrt is an ABRT from the ACSE service user carrying an OSI-AssoAbr.
func e2eAbrt(pci int, assoAbort []byte) []byte {
	return T(0x64, Int(0x80, AbortSourceUser), e2eExternal(pci, assoAbort))
}
