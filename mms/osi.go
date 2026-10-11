package mms

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Params are the OSI addressing and ACSE parameters of an association.
type Params struct {
	// Transport, session and presentation selectors of both ends
	// (defaults 0x0001, 0x0001 and 0x00000001).
	LocalTSel, RemoteTSel []byte
	LocalSSel, RemoteSSel []byte
	LocalPSel, RemotePSel []byte
	// AP titles (dotted OIDs) and AE qualifiers; empty titles are left out.
	LocalAPTitle, RemoteAPTitle string
	LocalAEQual, RemoteAEQual   int
	// Password turns on ACSE password authentication (mechanism 2.2.3.1).
	Password string
	// Auth turns on certificate-based ACSE authentication (IEC 62351-4
	// A-security profile, acseauth.go); Password is then ignored.
	Auth *CertAuth
	// MaxTPDU is the proposed COTP TPDU size (default 8192).
	MaxTPDU int
	// E2E turns on IEC 62351-4 end-to-end security (e2e.go); it excludes
	// Password and Auth (15.2.2).
	E2E *E2E
}

func (p Params) withDefaults() Params {
	def := func(b []byte, d ...byte) []byte {
		if len(b) == 0 {
			return d
		}
		return b
	}
	p.LocalTSel, p.RemoteTSel = def(p.LocalTSel, 0, 1), def(p.RemoteTSel, 0, 1)
	p.LocalSSel, p.RemoteSSel = def(p.LocalSSel, 0, 1), def(p.RemoteSSel, 0, 1)
	p.LocalPSel, p.RemotePSel = def(p.LocalPSel, 0, 0, 0, 1), def(p.RemotePSel, 0, 0, 0, 1)
	if p.MaxTPDU == 0 {
		p.MaxTPDU = 8192
	}
	return p
}

// Object identifiers of the association.
const (
	oidACSE        = "2.2.1.0.1"    // ACSE abstract syntax
	oidMMS         = "1.0.9506.2.1" // MMS abstract syntax
	oidBER         = "2.1.1"        // basic encoding rules
	oidMMSContext  = "1.0.9506.2.3" // MMS application context
	oidPasswordAut = "2.2.3.1"      // ACSE password authentication
)

// Presentation context identifiers this implementation proposes.
const (
	ctxACSE = 1
	ctxMMS  = 3
)

// ---- TPKT and COTP -----------------------------------------------------------

// transport frames COTP class 0 TPDUs in TPKT on a TCP connection.
type transport struct {
	c       net.Conn
	r       *bufio.Reader
	wmu     sync.Mutex
	maxData int // user data per DT TPDU
	// calledTSel and callingTSel are the selectors of a received CR;
	// expectTSel, when set, is the only called selector accepted.
	calledTSel, callingTSel, expectTSel []byte
	// e2e is the association's IEC 62351-4 E2E state; smu orders the
	// protection and sending of MMS PDUs.
	e2e *e2eSession
	smu sync.Mutex
}

// isTLS reports whether the transport runs over TLS (confParams).
func (t *transport) isTLS() bool {
	_, ok := t.c.(interface{ Handshake() error })
	return ok
}

// sendMMS sends an MMS PDU in the MMS presentation context, or protected
// by E2E security in its context.
func (t *transport) sendMMS(ctx int, pdu []byte) error {
	if t.e2e == nil {
		return t.writeTSDU(sessionData(pdv(ctx, pdu)))
	}
	t.smu.Lock()
	defer t.smu.Unlock()
	b, err := t.e2e.wrap(pdu)
	if err != nil {
		return err
	}
	return t.writeTSDU(sessionData(pdv(t.e2e.pciE2E, b)))
}

// recvMMS returns the MMS PDU of presentation user data; with E2E a
// failed check aborts the association with a DtSecAbort (14.4.1).
func (t *transport) recvMMS(user []byte) ([]byte, error) {
	ctx, pdu, err := userDataPDU(user)
	if err != nil || t.e2e == nil {
		return pdu, err
	}
	var out []byte
	if ctx != t.e2e.pciE2E {
		err = dtErr(DDEncryptionRequired, "an MMS PDU outside E2E security")
	} else {
		out, err = t.e2e.unwrap(pdu)
	}
	if err != nil {
		t.e2e.e.auth.event(EvE2EDataTransfer, t.c.RemoteAddr().String(), map[string]string{"clause": "IEC 62351-4 14.4",
			"association": t.e2e.assoID, "reason": err.Error(), "method": "e2e"})
		_ = t.userAbort(t.e2e.dtAbort(err))
		_ = t.c.Close()
		return nil, err
	}
	return out, nil
}

func newTransport(c net.Conn) *transport {
	return &transport{c: c, r: bufio.NewReaderSize(c, 65536), maxData: 8192 - 3}
}

// readTPKT reads one TPKT packet's payload (a COTP TPDU).
func (t *transport) readTPKT() ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(t.r, h[:]); err != nil {
		return nil, err
	}
	if h[0] != 3 {
		return nil, fmt.Errorf("tpkt: version %d", h[0])
	}
	n := int(binary.BigEndian.Uint16(h[2:]))
	if n < 7 {
		return nil, fmt.Errorf("tpkt: length %d", n)
	}
	b := make([]byte, n-4)
	if _, err := io.ReadFull(t.r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func (t *transport) writeTPKT(tpdu ...[]byte) error {
	n := 4
	for _, p := range tpdu {
		n += len(p)
	}
	if n > 0xffff {
		return errors.New("tpkt: packet too long")
	}
	b := make([]byte, 4, n)
	b[0] = 3
	binary.BigEndian.PutUint16(b[2:], uint16(n))
	for _, p := range tpdu {
		b = append(b, p...)
	}
	_, err := t.c.Write(b)
	return err
}

// COTP TPDU codes.
const (
	cotpCR = 0xe0
	cotpCC = 0xd0
	cotpDR = 0x80
	cotpDT = 0xf0
	cotpER = 0x70
)

func tpduSizeCode(n int) byte {
	code := byte(7)
	for s := 128; s < n && code < 13; s <<= 1 {
		code++
	}
	return code
}

// cotpParams encodes the TPDU size and TSAP parameters.
func cotpParams(size int, calling, called []byte) []byte {
	p := []byte{0xc0, 1, tpduSizeCode(size)}
	if calling != nil {
		p = append(append(p, 0xc1, byte(len(calling))), calling...)
	}
	if called != nil {
		p = append(append(p, 0xc2, byte(len(called))), called...)
	}
	return p
}

func parseCOTPParams(b []byte) map[byte][]byte {
	out := map[byte][]byte{}
	for len(b) >= 2 {
		code, n := b[0], int(b[1])
		if 2+n > len(b) {
			break
		}
		out[code] = b[2 : 2+n]
		b = b[2+n:]
	}
	return out
}

func (t *transport) setTPDUSize(code []byte) {
	if len(code) == 1 && code[0] >= 7 && code[0] <= 13 {
		t.maxData = (1 << code[0]) - 3
	}
}

// connect sends CR and waits for CC.
func (t *transport) connect(p Params) error {
	params := cotpParams(p.MaxTPDU, p.LocalTSel, p.RemoteTSel)
	cr := append([]byte{byte(6 + len(params)), cotpCR, 0, 0, 0, 1, 0}, params...)
	if err := t.writeTPKT(cr); err != nil {
		return err
	}
	b, err := t.readTPKT()
	if err != nil {
		return err
	}
	if len(b) < 7 || int(b[0])+1 > len(b) {
		return errors.New("cotp: a short connection confirm")
	}
	switch b[1] & 0xf0 {
	case cotpCC:
	case cotpDR:
		return errors.New("cotp: the peer refused the transport connection")
	default:
		return fmt.Errorf("cotp: TPDU %#x instead of a connection confirm", b[1])
	}
	t.setTPDUSize(parseCOTPParams(b[7 : int(b[0])+1])[0xc0])
	return nil
}

// accept waits for CR and answers CC.
func (t *transport) accept() error {
	b, err := t.readTPKT()
	if err != nil {
		return err
	}
	if len(b) < 7 || b[1]&0xf0 != cotpCR || int(b[0])+1 > len(b) {
		return errors.New("cotp: expected a connection request")
	}
	ps := parseCOTPParams(b[7 : int(b[0])+1])
	t.calledTSel, t.callingTSel = ps[0xc2], ps[0xc1]
	if len(t.expectTSel) > 0 && !bytes.Equal(t.calledTSel, t.expectTSel) {
		// Disconnect request, reason 3: address unknown (class 0).
		dr := []byte{6, cotpDR, b[4], b[5], 0, 0, 3}
		_ = t.writeTPKT(dr)
		return fmt.Errorf("%w: called transport selector %x", ErrRejected, t.calledTSel)
	}
	size := 8192
	if c := ps[0xc0]; len(c) == 1 && c[0] >= 7 && c[0] <= 13 {
		size = 1 << c[0]
	}
	t.maxData = size - 3
	params := cotpParams(size, ps[0xc2], ps[0xc1])
	cc := append([]byte{byte(6 + len(params)), cotpCC, b[4], b[5], 0, 2, 0}, params...)
	return t.writeTPKT(cc)
}

// readTSDU reads DT TPDUs up to the one marked end of TSDU.
func (t *transport) readTSDU() ([]byte, error) {
	var out []byte
	for {
		b, err := t.readTPKT()
		if err != nil {
			return nil, err
		}
		if len(b) < 3 {
			return nil, errors.New("cotp: a short TPDU")
		}
		switch b[1] & 0xf0 {
		case cotpDT:
		case cotpDR:
			return nil, io.EOF
		case cotpER:
			return nil, errors.New("cotp: the peer reported a TPDU error")
		default:
			return nil, fmt.Errorf("cotp: unexpected TPDU %#x", b[1])
		}
		li := int(b[0])
		if li+1 > len(b) {
			return nil, errors.New("cotp: a bad length indicator")
		}
		out = append(out, b[li+1:]...)
		if b[2]&0x80 != 0 {
			return out, nil
		}
		if len(out) > 1<<24 {
			return nil, errors.New("cotp: TSDU too long")
		}
	}
}

// writeTSDU sends data in as many DT TPDUs as the TPDU size needs.
func (t *transport) writeTSDU(data []byte) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	for {
		n := min(len(data), t.maxData)
		eot := byte(0)
		if n == len(data) {
			eot = 0x80
		}
		if err := t.writeTPKT([]byte{2, cotpDT, eot}, data[:n]); err != nil {
			return err
		}
		data = data[n:]
		if eot != 0 {
			return nil
		}
	}
}

// ---- session ----------------------------------------------------------------

// Session SPDU identifiers.
const (
	spduData       = 0x01 // data transfer (after give tokens, also 0x01)
	spduFinish     = 0x09
	spduDisconnect = 0x0a
	spduRefuse     = 0x0c
	spduConnect    = 0x0d
	spduAccept     = 0x0e
	spduAbort      = 0x19
)

func sessLen(b []byte, n int) []byte {
	if n < 255 {
		return append(b, byte(n))
	}
	return append(b, 0xff, byte(n>>8), byte(n))
}

func sessParam(code byte, v []byte) []byte {
	return append(sessLen([]byte{code}, len(v)), v...)
}

// spdu builds an SPDU with the given parameters.
func spdu(si byte, params ...[]byte) []byte {
	var body []byte
	for _, p := range params {
		body = append(body, p...)
	}
	return append(sessLen([]byte{si}, len(body)), body...)
}

// parseSPDU reads the first SPDU: its identifier, parameter field and the
// rest of the buffer.
func parseSPDU(b []byte) (si byte, params, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errors.New("session: a short SPDU")
	}
	si = b[0]
	n, i := int(b[1]), 2
	if n == 0xff {
		if len(b) < 4 {
			return 0, nil, nil, errors.New("session: a short SPDU")
		}
		n, i = int(binary.BigEndian.Uint16(b[2:])), 4
	}
	if i+n > len(b) {
		return 0, nil, nil, errors.New("session: an SPDU longer than its TSDU")
	}
	return si, b[i : i+n], b[i+n:], nil
}

// sessUserData finds the user data parameter (PGI 193) of an SPDU.
func sessUserData(params []byte) []byte {
	for len(params) >= 2 {
		code := params[0]
		n, i := int(params[1]), 2
		if n == 0xff {
			if len(params) < 4 {
				return nil
			}
			n, i = int(binary.BigEndian.Uint16(params[2:])), 4
		}
		if i+n > len(params) {
			return nil
		}
		if code == 0xc1 || code == 0xc2 { // user data, extended user data
			return params[i : i+n]
		}
		params = params[i+n:]
	}
	return nil
}

func connectItems() []byte {
	// Connect/accept item: protocol options 0, version 2.
	item := append(sessParam(19, []byte{0}), sessParam(22, []byte{2})...)
	return sessParam(5, item)
}

// sessionData wraps presentation data in give-tokens and data transfer.
func sessionData(ppdu []byte) []byte {
	return append([]byte{spduData, 0, spduData, 0}, ppdu...)
}

// ---- presentation and ACSE ---------------------------------------------------

// pdv wraps a PDU as fully encoded user data in a presentation context.
func pdv(ctx int, pdu []byte) []byte {
	return T(0x61, T(0x30, Int(0x02, int64(ctx)), T(0xa0, pdu)))
}

// userDataPDU extracts the single-ASN1-type PDU from fully encoded data.
func userDataPDU(b []byte) (ctx int, pdu []byte, err error) {
	e, _, err := Parse(b)
	if err != nil {
		return 0, nil, err
	}
	if e.Tag != 0x61 {
		return 0, nil, fmt.Errorf("presentation: user data with tag %#x", e.Tag)
	}
	lists, err := e.Children()
	if err != nil || len(lists) == 0 {
		return 0, nil, errors.New("presentation: empty user data")
	}
	parts, err := lists[0].Children()
	if err != nil {
		return 0, nil, err
	}
	for _, p := range parts {
		switch {
		case p.Tag == 0x02:
			v, _ := DecodeInt(p.Val)
			ctx = int(v)
		case p.Tag == 0xa0:
			return ctx, p.Val, nil
		}
	}
	return 0, nil, errors.New("presentation: no single-ASN1-type data value")
}

func contextDefinition(id int, abstract string) []byte {
	return T(0x30, Int(0x02, int64(id)), T(0x06, OID(abstract)), T(0x30, T(0x06, OID(oidBER))))
}

func apTitle(tag byte, oid string) []byte {
	if oid == "" {
		return nil
	}
	return T(tag, T(0x06, OID(oid)))
}

func aeQual(tag byte, oid string, q int) []byte {
	if oid == "" {
		return nil
	}
	return T(tag, Int(0x02, int64(q)))
}

// external wraps an MMS PDU as ACSE user information.
func external(mmsPDU []byte) []byte {
	return T(0xbe, T(0x28, T(0x06, OID(oidBER)), Int(0x02, ctxMMS), T(0xa0, mmsPDU)))
}

// aarq builds the ACSE association request carrying the MMS initiate
// (with E2E, e2eUI is the user information holding the HandshakeReq).
func aarq(p Params, initiate []byte, e2eUI ...[]byte) ([]byte, error) {
	appCtx := oidMMSContext
	if p.E2E != nil {
		appCtx = OIDE2EMMSContext
	}
	parts := [][]byte{
		T(0x80, []byte{7, 0x80}), // protocol-version 1
		T(0xa1, T(0x06, OID(appCtx))),
		apTitle(0xa2, p.RemoteAPTitle), aeQual(0xa3, p.RemoteAPTitle, p.RemoteAEQual),
		apTitle(0xa6, p.LocalAPTitle), aeQual(0xa7, p.LocalAPTitle, p.LocalAEQual),
	}
	switch {
	case p.Auth != nil:
		pci := 0
		if p.Auth.offer {
			pci = ctxAuth
		}
		v, err := p.Auth.value(pci)
		if err != nil {
			return nil, err
		}
		parts = append(parts,
			T(0x8a, acseRequirementsAuth), // sender-acse-requirements: authentication (62351-4 11.1.4.1)
			T(0x8b, OID(OIDAuthMechanism)),
			T(0xac, v))
	case p.E2E != nil:
	case p.Password != "":
		parts = append(parts,
			T(0x8a, acseRequirementsAuth), // sender requirements: authentication
			T(0x8b, OID(oidPasswordAut)),
			T(0xac, Str(0x80, p.Password)))
	}
	if p.E2E != nil {
		parts = append(parts, e2eUI...)
	} else {
		parts = append(parts, external(initiate))
	}
	return T(0x60, parts...), nil
}

// cpType builds the presentation connect PPDU around an AARQ.
func cpType(p Params, aarqPDU []byte) []byte {
	ctxs := [][]byte{contextDefinition(ctxACSE, oidACSE), contextDefinition(ctxMMS, oidMMS)}
	if p.Auth != nil && p.Auth.offer {
		ctxs = append(ctxs, contextDefinition(ctxAuth, OIDAuthSyntax))
	}
	if p.E2E != nil {
		ctxs = append(ctxs, contextDefinition(ctxE2E, OIDE2ESyntax))
	}
	return T(0x31,
		T(0xa0, Int(0x80, 1)),
		T(0xa2,
			T(0x81, p.LocalPSel), T(0x82, p.RemotePSel),
			T(0xa4, ctxs...),
			pdv(ctxACSE, aarqPDU)))
}

// ACSE results.
const (
	ACSEAccepted          = 0
	ACSERejectedPermanent = 1
)

// ACSE diagnostics of the service user (ITU-T X.227
// Associate-source-diagnostic acse-service-user; IEC 62351-4 Annex I).
const (
	DiagNull                 = 0
	DiagNoReason             = 1
	DiagNotRecognised        = 2 // application-context-name-not-supported
	DiagCallingAPTitle       = 3
	DiagCallingAEQualifier   = 5
	DiagCalledAPTitle        = 7
	DiagCalledAEQualifier    = 9
	DiagAuthMechanism        = 11 // authentication-mechanism-name-not-recognized
	DiagAuthMechanismMissing = 12 // authentication-mechanism-name-required
	DiagAuthFailure          = 13
	DiagAuthRequired         = 14
)

// aare builds the ACSE association response. auth, when set, is the
// responding authentication value (with the requirements bit and the
// mechanism name).
func aare(result, diag int, initiate, auth []byte, responding ...[]byte) []byte {
	return aareCtx(oidMMSContext, result, diag, initiate, auth, nil, responding...)
}

// aareCtx is aare with the application context name and, for E2E, the
// user information to send instead of the initiate response.
func aareCtx(appCtx string, result, diag int, initiate, auth, userInfo []byte, responding ...[]byte) []byte {
	parts := [][]byte{
		T(0x80, []byte{7, 0x80}),
		T(0xa1, T(0x06, OID(appCtx))),
		T(0xa2, Int(0x02, int64(result))),
		T(0xa3, T(0xa1, Int(0x02, int64(diag)))),
	}
	parts = append(parts, responding...) // responding-AP-title [4], responding-AE-qualifier [5]
	if auth != nil {
		parts = append(parts, T(0x88, acseRequirementsAuth), T(0x89, OID(OIDAuthMechanism)), T(0xaa, auth))
	}
	switch {
	case userInfo != nil:
		parts = append(parts, userInfo)
	case initiate != nil:
		parts = append(parts, external(initiate))
	}
	return T(0x61, parts...)
}

// presContext is a proposed presentation context.
type presContext struct {
	id       int
	abstract string
}

// cpaType builds the presentation accept PPDU around an AARE, with one
// result per proposed context: acceptance for ACSE, MMS and the
// authentication syntax, provider rejection (abstract syntax not
// supported) otherwise.
func cpaType(respPSel []byte, proposed []presContext, aarePDU []byte) []byte {
	var results [][]byte
	for _, c := range proposed {
		switch c.abstract {
		case oidACSE, oidMMS, OIDAuthSyntax, OIDE2ESyntax:
			results = append(results, T(0x30, Int(0x80, 0), T(0x81, OID(oidBER))))
		default:
			results = append(results, T(0x30, Int(0x80, 2), Int(0x82, 1)))
		}
	}
	return T(0x31,
		T(0xa0, Int(0x80, 1)),
		T(0xa2, T(0x83, respPSel), T(0xa5, results...), pdv(ctxACSE, aarePDU)))
}

// proposedContexts reads the presentation context definition list of a
// CP PPDU.
func proposedContexts(ppdu []byte) []presContext {
	e, _, err := Parse(ppdu)
	if err != nil {
		return nil
	}
	kids, _ := e.Children()
	for _, k := range kids {
		if k.Tag != 0xa2 {
			continue
		}
		items, _ := k.Children()
		for _, it := range items {
			if it.Tag != 0xa4 {
				continue
			}
			defs, _ := it.Children()
			var out []presContext
			for _, d := range defs {
				fs, _ := d.Children()
				var c presContext
				for _, f := range fs {
					switch f.Tag {
					case 0x02:
						v, _ := DecodeInt(f.Val)
						c.id = int(v)
					case 0x06:
						c.abstract = DecodeOID(f.Val)
					}
				}
				out = append(out, c)
			}
			return out
		}
	}
	return nil
}

// findUserData walks a CP or CPA PPDU to its fully encoded user data.
func findUserData(ppdu []byte) ([]byte, error) {
	e, _, err := Parse(ppdu)
	if err != nil {
		return nil, err
	}
	if e.Tag != 0x31 {
		return nil, fmt.Errorf("presentation: connect PPDU with tag %#x", e.Tag)
	}
	kids, err := e.Children()
	if err != nil {
		return nil, err
	}
	for _, k := range kids {
		if k.Tag != 0xa2 {
			continue
		}
		items, err := k.Children()
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			if it.Tag == 0x61 {
				return T(0x61, it.Val), nil
			}
		}
	}
	return nil, errors.New("presentation: no user data in the connect PPDU")
}

// acseFields decodes an AARQ or AARE into its tagged fields.
func acseFields(pdu []byte, want byte) (map[byte]Elem, error) {
	e, _, err := Parse(pdu)
	if err != nil {
		return nil, err
	}
	if e.Tag != want {
		return nil, fmt.Errorf("acse: PDU tag %#x, want %#x", e.Tag, want)
	}
	kids, err := e.Children()
	if err != nil {
		return nil, err
	}
	out := map[byte]Elem{}
	for _, k := range kids {
		out[k.Tag] = k
	}
	return out, nil
}

// externalMMS extracts the MMS PDU from ACSE user information.
func externalMMS(ui Elem) ([]byte, error) {
	ext, _, err := Parse(ui.Val)
	if err != nil {
		return nil, err
	}
	parts, err := ext.Children()
	if err != nil {
		return nil, err
	}
	for _, p := range parts {
		if p.Tag == 0xa0 {
			return p.Val, nil
		}
	}
	return nil, errors.New("acse: no MMS PDU in the user information")
}

// ---- client-side association -------------------------------------------------

// ErrRejected is wrapped by Dial when the peer refuses the association.
var ErrRejected = errors.New("the IED refused the association")

// associate runs COTP connect, session connect, presentation connect and
// ACSE association with the MMS initiate request, and returns the initiate
// response PDU.
func associate(t *transport, p Params, initiate []byte, deadline time.Time) ([]byte, error) {
	_ = t.c.SetDeadline(deadline)
	defer func() { _ = t.c.SetDeadline(time.Time{}) }()
	if err := t.connect(p); err != nil {
		return nil, err
	}
	var hs *e2eClientHS
	var e2eUI []byte
	if p.E2E != nil {
		if p.Auth != nil || p.Password != "" {
			return nil, errors.New("mms: E2E security excludes ACSE authentication (IEC 62351-4 15.2.2)")
		}
		var req []byte
		var err error
		if hs, req, err = p.E2E.clientHello(initiate, ctxMMS, ctxE2E, t.isTLS()); err != nil {
			return nil, err
		}
		e2eUI = e2eExternal(ctxE2E, req)
	}
	rq, err := aarq(p, initiate, e2eUI)
	if err != nil {
		return nil, err
	}
	cp := cpType(p, rq)
	// User data above 512 octets goes in the extended user data parameter
	// of the CONNECT SPDU (session version 2; IEC 62351-4 10.3, G.3).
	udCode := byte(0xc1)
	if len(cp) > 512 {
		udCode = 0xc2
	}
	conn := spdu(spduConnect, connectItems(), sessParam(20, []byte{0, 2}),
		sessParam(51, p.LocalSSel), sessParam(52, p.RemoteSSel), sessParam(udCode, cp))
	if err := t.writeTSDU(conn); err != nil {
		return nil, err
	}
	b, err := t.readTSDU()
	if err != nil {
		return nil, err
	}
	si, params, _, err := parseSPDU(b)
	if err != nil {
		return nil, err
	}
	switch si {
	case spduAccept:
	case spduRefuse:
		return nil, fmt.Errorf("%w: the session connection was refused", ErrRejected)
	case spduAbort:
		return nil, fmt.Errorf("%w: the session was aborted", ErrRejected)
	default:
		return nil, fmt.Errorf("session: SPDU %#x instead of accept", si)
	}
	ud, err := findUserData(sessUserData(params))
	if err != nil {
		return nil, err
	}
	_, pdu, err := userDataPDU(ud)
	if err != nil {
		return nil, err
	}
	f, err := acseFields(pdu, 0x61)
	if err != nil {
		return nil, err
	}
	res := -1
	if r, ok := f[0xa2]; ok {
		if in, _, err := Parse(r.Val); err == nil {
			v, _ := DecodeInt(in.Val)
			res = int(v)
		}
	}
	if res != ACSEAccepted && hs != nil {
		if ui, ok := f[0xbe]; ok {
			if _, rsp, err := e2eFromExternal(ui); err == nil {
				if _, _, err := hs.finish(rsp, t.c.RemoteAddr().String(), t.isTLS()); err != nil {
					return nil, err
				}
			}
		}
	}
	if res != ACSEAccepted {
		diag := 0
		if d, ok := f[0xa3]; ok {
			if src, _, err := Parse(d.Val); err == nil {
				if in, _, err := Parse(src.Val); err == nil {
					v, _ := DecodeInt(in.Val)
					diag = int(v)
				}
			}
		}
		switch diag {
		case DiagAuthFailure, DiagAuthRequired:
			return nil, fmt.Errorf("%w: authentication failed (ACSE diagnostic %d)", ErrRejected, diag)
		case DiagAuthMechanism, DiagAuthMechanismMissing:
			return nil, fmt.Errorf("%w: the peer wants another authentication mechanism (ACSE diagnostic %d)", ErrRejected, diag)
		}
		return nil, fmt.Errorf("%w: ACSE result %d, diagnostic %d", ErrRejected, res, diag)
	}
	if p.Auth != nil {
		if err := checkAARE(t, p.Auth, f); err != nil {
			return nil, err
		}
	}
	if hs != nil {
		peer := t.c.RemoteAddr().String()
		ui, ok := f[0xbe]
		if !ok {
			_ = t.userAbort(e2eAbrt(ctxE2E, p.E2E.secAbort(0xa0, hs.assoID, HDProtocolError)))
			return nil, fmt.Errorf("%w: the AARE has no E2E handshake response", ErrAuthentication)
		}
		_, rsp, err := e2eFromExternal(ui)
		if err != nil {
			return nil, err
		}
		resp, sess, err := hs.finish(rsp, peer, t.isTLS())
		if err != nil {
			var ee *E2EError
			if errors.As(err, &ee) {
				p.E2E.auth.event(EvE2EHandshake, peer, map[string]string{"clause": "IEC 62351-4 14.3", "reason": err.Error(), "method": "e2e"})
				_ = t.userAbort(e2eAbrt(ctxE2E, p.E2E.secAbort(0xa0, hs.assoID, errDiag(err))))
			}
			return nil, err
		}
		t.e2e = sess
		return resp, nil
	}
	ui, ok := f[0xbe]
	if !ok {
		return nil, errors.New("acse: the response has no MMS initiate response")
	}
	return externalMMS(ui)
}

// checkAARE verifies the responder's authentication in an accepted AARE
// (IEC 62351-4 11.2.4.2): a missing mechanism name or value is answered
// with an ABRT from the ACSE service provider, a failed check of the value
// with a presentation provider abort.
func checkAARE(t *transport, a *CertAuth, f map[byte]Elem) error {
	peer := t.c.RemoteAddr().String()
	mech, ok := f[0x89]
	if !ok {
		a.event(EvAuthMechMissing, peer, map[string]string{"reason": "the AARE has no mechanism name"})
		_ = t.userAbort(abrt(AbortSourceProvider, AbortDiagMechRequired))
		return fmt.Errorf("%w: the AARE has no authentication mechanism name", ErrAuthentication)
	}
	if !sameOID(mech, OIDAuthMechanism) {
		a.event(EvAuthMechUnknown, peer, map[string]string{"mechanism": DecodeOID(mech.Val)})
		_ = t.userAbort(abrt(AbortSourceProvider, AbortDiagMechUnrecognised))
		return fmt.Errorf("%w: the AARE names mechanism %s", ErrAuthentication, DecodeOID(mech.Val))
	}
	v, ok := f[0xaa]
	if !ok {
		a.event(EvAuthValueInvalid, peer, map[string]string{"reason": "the AARE has no responding authentication value"})
		_ = t.userAbort(abrt(AbortSourceProvider, AbortDiagAuthRequired))
		return fmt.Errorf("%w: the AARE has no authentication value", ErrAuthentication)
	}
	if _, err := a.check(v.Val, peer); err != nil {
		_ = t.providerAbort()
		return err
	}
	return nil
}

// ---- server-side association -------------------------------------------------

// Association is what a server learns from a client's association request.
type Association struct {
	// CallingAPTitle is the calling AP title: a dotted object identifier
	// (form 2) or, in form 1, the directory name as text (RFC 4514).
	CallingAPTitle string
	// CallingAPTitleForm is 1 or 2 (0 when absent).
	CallingAPTitleForm int
	// CallingAEQualifier is the calling AE qualifier in form 2; in form 1
	// (a relative distinguished name) it is in CallingAEQualifierName.
	CallingAEQualifier     *int
	CallingAEQualifierName string
	// CalledAPTitle and CalledAEQualifier are what the client asked for,
	// in the same forms.
	CalledAPTitle     string
	CalledAEQualifier *int
	// Selectors of the client and those it called.
	CallingTSel, CallingSSel, CallingPSel []byte
	CalledTSel, CalledSSel, CalledPSel    []byte
	// AuthMechanism is the mechanism name of the ACSE authentication (a
	// dotted object identifier) and AuthValue the encoded
	// calling-authentication-value, when present.
	AuthMechanism string
	AuthValue     []byte
	Password      string // ACSE password, when the client sent one
	// PeerCertificate is the client's certificate when certificate-based
	// ACSE authentication succeeded (AcceptOptions.Auth), for binding to
	// the peer's configuration (IEC 62351-4 5.1).
	PeerCertificate *x509.Certificate
	Initiate        []byte // MMS initiate-RequestPDU
}

// ServerConn is the server end of an MMS association.
type ServerConn struct {
	t      *transport
	mmsCtx int
	closed chan struct{}
	once   sync.Once
}

// AcceptOptions configure AcceptAssociationWith.
type AcceptOptions struct {
	// LocalTSel, LocalSSel and LocalPSel, when set, are the only called
	// selectors accepted: another is refused with a transport disconnect,
	// a session refuse or a presentation connect reject.
	LocalTSel, LocalSSel, LocalPSel []byte
	// LocalAPTitle and LocalAEQual, when set, are this server's AP title
	// (form 2) and AE qualifier: a request calling another is refused
	// (called-AP-title-not-recognized, called-AE-qualifier-not-recognized)
	// and the AARE names them as the responding AP title and qualifier.
	// Without them the AARE repeats the called ones (IEC 62351-4 10.5.3).
	LocalAPTitle string
	LocalAEQual  *int
	// Auth requires certificate-based ACSE authentication of every client
	// (IEC 62351-4 A-security profile) and authenticates the server in the
	// AARE.
	Auth *CertAuth
	// E2E requires IEC 62351-4 end-to-end security of every association
	// (e2e.go); Association.PeerCertificate is then the E2E certificate.
	E2E *E2E
}

// AcceptAssociation runs the server side of the connection establishment
// up to the association request. The caller decides with decide, which
// returns the ACSE result and diagnostic and the MMS initiate response.
func AcceptAssociation(c net.Conn, decide func(Association) (result, diag int, initiateResp []byte)) (*ServerConn, error) {
	return AcceptAssociationWith(c, AcceptOptions{}, decide)
}

// AcceptAssociationWith is AcceptAssociation with options. With Auth, a
// request without the mechanism name is refused with an AARE
// (rejected-permanent, authentication-mechanism-name-required), one with
// another mechanism with authentication-mechanism-name-not-recognized, and
// a failed check of the authentication value (certificate, time, replay,
// signature) with a presentation provider abort (IEC 62351-4 11.2.3.2);
// decide is called only for an authenticated client, and an accepted AARE
// carries the server's authentication value (11.2.4.1).
func AcceptAssociationWith(c net.Conn, o AcceptOptions, decide func(Association) (result, diag int, initiateResp []byte)) (*ServerConn, error) {
	t := newTransport(c)
	if len(o.LocalTSel) > 0 {
		t.expectTSel = o.LocalTSel
	}
	if err := t.accept(); err != nil {
		return nil, err
	}
	b, err := t.readTSDU()
	if err != nil {
		return nil, err
	}
	si, params, _, err := parseSPDU(b)
	if err != nil {
		return nil, err
	}
	if si != spduConnect {
		return nil, fmt.Errorf("session: SPDU %#x instead of connect", si)
	}
	callingSSel, calledSSel := sessParamValue(params, 51), sessParamValue(params, 52)
	if len(o.LocalSSel) > 0 && !bytes.Equal(calledSSel, o.LocalSSel) {
		// Refuse: SSAP unknown (reason code 0x81).
		_ = t.writeTSDU(spdu(spduRefuse, sessParam(50, []byte{0x81})))
		_ = c.Close()
		return nil, fmt.Errorf("%w: called session selector %x", ErrRejected, calledSSel)
	}
	cp := sessUserData(params)
	callingPSel, calledPSel := cpSelectors(cp)
	if len(o.LocalPSel) > 0 && !bytes.Equal(calledPSel, o.LocalPSel) {
		// Presentation connect reject: called presentation address unknown
		// (provider reason 3), carried by a session refuse from the user.
		cpr := T(0x30, Int(0x8a, 3))
		_ = t.writeTSDU(spdu(spduRefuse, sessParam(50, append([]byte{2}, cpr...))))
		_ = c.Close()
		return nil, fmt.Errorf("%w: called presentation selector %x", ErrRejected, calledPSel)
	}
	ud, err := findUserData(cp)
	if err != nil {
		return nil, err
	}
	_, pdu, err := userDataPDU(ud)
	if err != nil {
		return nil, err
	}
	f, err := acseFields(pdu, 0x60)
	if err != nil {
		return nil, err
	}
	proposed := proposedContexts(cp)
	if len(proposed) == 0 {
		proposed = []presContext{{ctxACSE, oidACSE}, {ctxMMS, oidMMS}}
	}
	mmsCtx, authPCI, e2ePCI := ctxMMS, 0, 0
	for _, pc := range proposed {
		switch pc.abstract {
		case oidMMS:
			mmsCtx = pc.id
		case OIDAuthSyntax:
			authPCI = pc.id
		case OIDE2ESyntax:
			e2ePCI = pc.id
		}
	}
	a := Association{CallingTSel: t.callingTSel, CalledTSel: t.calledTSel, CallingSSel: callingSSel, CalledSSel: calledSSel,
		CallingPSel: callingPSel, CalledPSel: calledPSel}
	if e, ok := f[0xa6]; ok {
		a.CallingAPTitle, a.CallingAPTitleForm = decodeAPTitle(e)
	}
	if e, ok := f[0xa7]; ok {
		a.CallingAEQualifier, a.CallingAEQualifierName = decodeAEQualifier(e)
	}
	if e, ok := f[0xa2]; ok {
		a.CalledAPTitle, _ = decodeAPTitle(e)
	}
	if e, ok := f[0xa3]; ok {
		a.CalledAEQualifier, _ = decodeAEQualifier(e)
	}
	if e, ok := f[0x8b]; ok {
		a.AuthMechanism = DecodeOID(e.Val)
	}
	if e, ok := f[0xac]; ok {
		a.AuthValue = e.Val
	}
	if e, ok := f[0xac]; ok {
		if in, _, err := Parse(e.Val); err == nil && in.Tag == 0x80 { // charstring
			a.Password = string(in.Val)
		}
	}
	if ui, ok := f[0xbe]; ok && o.E2E == nil {
		if a.Initiate, err = externalMMS(ui); err != nil {
			return nil, err
		}
	}
	// The responding AP title and AE qualifier: ours, else the called ones.
	var responding [][]byte
	switch {
	case o.LocalAPTitle != "":
		responding = append(responding, T(0xa4, T(0x06, OID(o.LocalAPTitle))))
		if o.LocalAEQual != nil {
			responding = append(responding, T(0xa5, Int(0x02, int64(*o.LocalAEQual))))
		}
	default:
		if e, ok := f[0xa2]; ok {
			responding = append(responding, T(0xa4, e.Val))
		}
		if e, ok := f[0xa3]; ok {
			responding = append(responding, T(0xa5, e.Val))
		}
	}
	respPSel := calledPSel
	if len(respPSel) == 0 {
		respPSel = []byte{0, 0, 0, 1}
	}
	appCtx := oidMMSContext
	if o.E2E != nil {
		appCtx = OIDE2EMMSContext
	}
	var e2eUI []byte
	reply := func(res, diag int, resp, auth []byte) error {
		cpa := cpaType(respPSel, proposed, aareCtx(appCtx, res, diag, resp, auth, e2eUI, responding...))
		code := byte(0xc1)
		if len(cpa) > 512 {
			code = 0xc2
		}
		return t.writeTSDU(spdu(spduAccept, connectItems(), sessParam(20, []byte{0, 2}), sessParam(code, cpa)))
	}
	switch {
	case o.LocalAPTitle != "" && a.CalledAPTitle != "" && a.CalledAPTitle != o.LocalAPTitle:
		_ = reply(ACSERejectedPermanent, DiagCalledAPTitle, nil, nil)
		_ = c.Close()
		return nil, fmt.Errorf("%w: called AP title %s", ErrRejected, a.CalledAPTitle)
	case o.LocalAEQual != nil && a.CalledAEQualifier != nil && *a.CalledAEQualifier != *o.LocalAEQual:
		_ = reply(ACSERejectedPermanent, DiagCalledAEQualifier, nil, nil)
		_ = c.Close()
		return nil, fmt.Errorf("%w: called AE qualifier %d", ErrRejected, *a.CalledAEQualifier)
	}
	if o.Auth != nil {
		peer := c.RemoteAddr().String()
		mech, hasMech := f[0x8b]
		switch {
		case !hasMech:
			o.Auth.event(EvAuthMechMissing, peer, map[string]string{"reason": "the AARQ has no mechanism name", "calling_ap_title": a.CallingAPTitle})
			_ = reply(ACSERejectedPermanent, DiagAuthMechanismMissing, nil, nil)
			_ = c.Close()
			return nil, fmt.Errorf("%w: the AARQ has no authentication mechanism name", ErrAuthentication)
		case !sameOID(mech, OIDAuthMechanism):
			o.Auth.event(EvAuthMechUnknown, peer, map[string]string{"mechanism": DecodeOID(mech.Val), "calling_ap_title": a.CallingAPTitle})
			_ = reply(ACSERejectedPermanent, DiagAuthMechanism, nil, nil)
			_ = c.Close()
			return nil, fmt.Errorf("%w: the AARQ names mechanism %s", ErrAuthentication, DecodeOID(mech.Val))
		}
		v, ok := f[0xac]
		if !ok {
			o.Auth.event(EvAuthValueInvalid, peer, map[string]string{"reason": "the AARQ has no calling authentication value"})
			_ = reply(ACSERejectedPermanent, DiagAuthRequired, nil, nil)
			_ = c.Close()
			return nil, fmt.Errorf("%w: the AARQ has no authentication value", ErrAuthentication)
		}
		cert, err := o.Auth.check(v.Val, peer)
		if err != nil {
			_ = t.providerAbort()
			_ = c.Close()
			return nil, err
		}
		a.PeerCertificate = cert
	}
	var hs *e2eServerHS
	if o.E2E != nil {
		peer := c.RemoteAddr().String()
		ui, ok := f[0xbe]
		var req Elem
		var pci int
		if ok {
			pci, req, err = e2eFromExternal(ui)
		}
		switch {
		case !ok || err != nil || e2ePCI == 0 || pci != e2ePCI:
			err = hsErr(HDProtocolError, "the AARQ has no E2E handshake request in the e2eSecurityAS context")
		default:
			hs, err = o.E2E.serverCheck(req, mmsCtx, e2ePCI, peer)
		}
		if err != nil {
			o.E2E.auth.event(EvE2EHandshake, peer, map[string]string{"clause": "IEC 62351-4 14.3", "reason": err.Error(),
				"calling_ap_title": a.CallingAPTitle, "method": "e2e"})
			if e2ePCI != 0 {
				e2eUI = e2eExternal(e2ePCI, o.E2E.reject("", err))
			}
			_ = reply(ACSERejectedPermanent, DiagNoReason, nil, nil)
			_ = c.Close()
			return nil, err
		}
		a.Initiate, a.PeerCertificate = hs.initiate, hs.cert
	}
	res, diag, resp := decide(a)
	var sess *e2eSession
	if hs != nil {
		if res == ACSEAccepted {
			var acc []byte
			if acc, sess, err = hs.accept(resp, t.isTLS()); err != nil {
				_ = t.providerAbort()
				_ = c.Close()
				return nil, err
			}
			e2eUI, diag = e2eExternal(e2ePCI, acc), DiagNull
		} else {
			// ApplicationReject ([2] of HandshakeRsp) with the initiate
			// error as ApplData.
			parts := [][]byte{o.E2E.token3(hs.t.assoID)}
			if resp != nil {
				parts = append(parts, applData(mmsCtx, resp))
			}
			rj, _ := o.E2E.signed(0xa2, parts...)
			e2eUI, diag = e2eExternal(e2ePCI, rj), DiagNoReason
		}
	}
	var auth []byte
	if o.Auth != nil && res == ACSEAccepted {
		if auth, err = o.Auth.value(authPCI); err != nil {
			_ = t.providerAbort()
			_ = c.Close()
			return nil, err
		}
	}
	if err := reply(res, diag, resp, auth); err != nil {
		return nil, err
	}
	if res != ACSEAccepted {
		_ = c.Close()
		return nil, fmt.Errorf("%w: diagnostic %d", ErrRejected, diag)
	}
	t.e2e = sess
	return &ServerConn{t: t, mmsCtx: mmsCtx, closed: make(chan struct{})}, nil
}

// decodeAPTitle reads an AP title: form 2 (object identifier) as dotted
// text, form 1 (a directory name) as RFC 4514 text.
func decodeAPTitle(e Elem) (string, int) {
	in, _, err := Parse(e.Val)
	if err != nil {
		return "", 0
	}
	switch in.Tag {
	case 0x06:
		return DecodeOID(in.Val), 2
	case 0x30: // Name: RDNSequence
		var rdns pkix.RDNSequence
		if _, err := asn1.Unmarshal(e.Val, &rdns); err == nil {
			return rdns.String(), 1
		}
	}
	return "", 0
}

// decodeAEQualifier reads an AE qualifier: form 2 (an integer) or form 1
// (a relative distinguished name, as RFC 4514 text).
func decodeAEQualifier(e Elem) (*int, string) {
	in, _, err := Parse(e.Val)
	if err != nil {
		return nil, ""
	}
	switch in.Tag {
	case 0x02:
		v, err := DecodeInt(in.Val)
		if err != nil {
			return nil, ""
		}
		q := int(v)
		return &q, ""
	case 0x31: // RelativeDistinguishedName: SET OF AttributeTypeAndValue
		var rdn pkix.RelativeDistinguishedNameSET
		if _, err := asn1.UnmarshalWithParams(e.Val, &rdn, "set"); err == nil {
			return nil, pkix.RDNSequence{rdn}.String()
		}
	}
	return nil, ""
}

// sessParamValue finds a parameter (PI) of an SPDU's parameter field.
func sessParamValue(params []byte, code byte) []byte {
	for len(params) >= 2 {
		c := params[0]
		n, i := int(params[1]), 2
		if n == 0xff {
			if len(params) < 4 {
				return nil
			}
			n, i = int(binary.BigEndian.Uint16(params[2:])), 4
		}
		if i+n > len(params) {
			return nil
		}
		if c == code {
			return params[i : i+n]
		}
		params = params[i+n:]
	}
	return nil
}

// cpSelectors reads the calling and called presentation selectors of a
// CP PPDU.
func cpSelectors(cp []byte) (calling, called []byte) {
	e, _, err := Parse(cp)
	if err != nil {
		return nil, nil
	}
	kids, _ := e.Children()
	for _, k := range kids {
		if k.Tag != 0xa2 {
			continue
		}
		items, _ := k.Children()
		for _, it := range items {
			switch it.Tag {
			case 0x81:
				calling = it.Val
			case 0x82:
				called = it.Val
			}
		}
	}
	return calling, called
}

// Receive reads the next MMS PDU. io.EOF means the client released or
// dropped the association.
func (s *ServerConn) Receive() ([]byte, error) {
	for {
		b, err := s.t.readTSDU()
		if err != nil {
			return nil, err
		}
		si, _, rest, err := parseSPDU(b)
		if err != nil {
			return nil, err
		}
		switch si {
		case spduData:
			// give tokens, then data transfer
			si2, _, user, err := parseSPDU(rest)
			if err != nil || si2 != spduData {
				return nil, errors.New("session: a data SPDU without data transfer")
			}
			pdu, err := s.t.recvMMS(user)
			if err != nil {
				return nil, err
			}
			return pdu, nil
		case spduFinish:
			// Release: answer the ACSE release request and close; with
			// E2E the RLRE carries a signed ReleaseRsp (13.1.11, 15.3.6).
			rlre := pdv(ctxACSE, T(0x63, Int(0x80, 0)))
			if s.t.e2e != nil {
				rsp, _ := s.t.e2e.e.signed(0x30, s.t.e2e.e.token3(s.t.e2e.assoID))
				rlre = pdv(ctxACSE, T(0x63, Int(0x80, 0), e2eExternal(s.t.e2e.pciE2E, rsp)))
			}
			_ = s.t.writeTSDU(spdu(spduDisconnect, sessParam(0xc1, rlre)))
			return nil, io.EOF
		case spduAbort:
			return nil, io.EOF
		default:
			return nil, fmt.Errorf("session: unexpected SPDU %#x", si)
		}
	}
}

// Send writes an MMS PDU.
func (s *ServerConn) Send(pdu []byte) error {
	return s.t.sendMMS(s.mmsCtx, pdu)
}

// Close drops the connection.
func (s *ServerConn) Close() error {
	var err error
	s.once.Do(func() {
		close(s.closed)
		err = s.t.c.Close()
	})
	return err
}
