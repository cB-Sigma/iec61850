package mms

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/cB-Sigma/iotsec"
)

// Client is an MMS association with a server (an IED).
type Client struct {
	t        *transport
	onReport func(InformationReport)
	onEvent  func(EventNotification)

	// neg is the negotiated initiate response; slots bound the confirmed
	// requests outstanding at the server to the negotiated
	// MaxServOutstandingCalled.
	neg   Initiate
	slots chan struct{}

	mu      sync.Mutex
	invoke  uint32
	pending map[uint32]chan reply
	conclud chan error
	err     error
	done    chan struct{}
}

type reply struct {
	body Elem
	err  error
}

// DialOptions configure Dial.
type DialOptions struct {
	Params Params
	// Timeout bounds connection and association (default 10s).
	Timeout time.Duration
	// OnReport receives every informationReport, on the client's read
	// goroutine; it must not call the client synchronously.
	OnReport func(InformationReport)
	// OnEvent receives every EventNotification (event.go), on the read
	// goroutine; it must not call the client synchronously.
	OnEvent func(EventNotification)
	// Dialer, when set, opens the TCP connection.
	Dialer func(ctx context.Context, addr string) (net.Conn, error)
	// Profile, when set, secures the transport below TPKT with a TLS
	// profile (IEC 62351-3 as IEC 62351-4 adds to it; see CheckTLSParams)
	// and makes 3782 the default port. The server name is the profile's
	// own, else the host dialled. A profile that renews keys on an idle
	// connection gets an Identify request as its keepalive
	// (iotsec.SetKeepalive); one that ends a connection whose peer does
	// not take part leaves the reconnect to the caller.
	Profile iotsec.TLSClient
	// TLS, when set and Profile is not, secures the transport with a
	// plain crypto/tls configuration (TLS 1.2 at least; no profile
	// checks or events).
	TLS *tls.Config
	// Capabilities, when set, are the services and parameter CBBs the
	// initiate request proposes (a profile's set, such as TASE.2's);
	// default ClientCapabilities.
	Capabilities *Capabilities
}

// Dial connects to addr (host:port, port 102 by default, 3782 with TLS)
// and associates.
func Dial(ctx context.Context, addr string, o DialOptions) (*Client, error) {
	addr = DefaultAddr(addr, o.TLS != nil || o.Profile != nil)
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	var nc net.Conn
	var err error
	if o.Dialer != nil {
		nc, err = o.Dialer(dctx, addr)
	} else {
		var d net.Dialer
		nc, err = d.DialContext(dctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	if o.Profile != nil {
		host, _, _ := net.SplitHostPort(addr)
		tc, err := o.Profile.Client(dctx, nc, "")
		if err != nil {
			_ = nc.Close()
			return nil, fmt.Errorf("mms: TLS handshake with %s: %w", host, err)
		}
		nc = tc
	} else if o.TLS != nil {
		cfg := o.TLS.Clone()
		if cfg.MinVersion < tls.VersionTLS12 {
			cfg.MinVersion = tls.VersionTLS12
		}
		if cfg.ServerName == "" && !cfg.InsecureSkipVerify {
			cfg.ServerName, _, _ = net.SplitHostPort(addr)
		}
		tc := tls.Client(nc, cfg)
		if err := tc.HandshakeContext(dctx); err != nil {
			_ = nc.Close()
			return nil, fmt.Errorf("mms: TLS handshake: %w", err)
		}
		nc = tc
	}
	t := newTransport(nc)
	deadline, _ := dctx.Deadline()
	caps := ClientCapabilities
	if o.Capabilities != nil {
		caps = *o.Capabilities
	}
	resp, err := associate(t, o.Params.withDefaults(), caps.Request().Encode(TagInitiateRequest), deadline)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	e, _, err := Parse(resp)
	if err != nil || e.Tag != TagInitiateResponse {
		_ = nc.Close()
		if err == nil && e.Tag == TagInitiateError {
			return nil, fmt.Errorf("%w: the MMS initiate was refused", ErrRejected)
		}
		return nil, errors.New("mms: the association did not carry an initiate response")
	}
	neg, err := DecodeInitiate(e)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	if neg.Version < 1 || neg.Version > MinorVersion {
		_ = nc.Close()
		return nil, fmt.Errorf("mms: the server answered minor version %d to a proposal of %d", neg.Version, MinorVersion)
	}
	// A negotiated count of 0 is allowed (8.2.1.2.3) but would stop every
	// request: one is kept.
	c := &Client{t: t, onReport: o.OnReport, onEvent: o.OnEvent, pending: map[uint32]chan reply{}, done: make(chan struct{}),
		neg: neg, slots: make(chan struct{}, max(1, neg.MaxServOutstandingCalled))}
	// Under the IEC 62351-3 profile a timed key update on an idle
	// association is preceded by an Identify request (the profile's
	// keepalive, iotsec.KeepaliveConn).
	iotsec.SetKeepalive(nc, c.tlsKeepalive)
	go c.readLoop()
	return c, nil
}

// tlsKeepalive is the TLS profile's keepalive: an Identify request (a
// service every MMS server provides, which reads no data and changes no
// state; ISO 9506-1 10.3), else Status (10.2) when the server's initiate
// response lists only that. It does not wait for the response.
func (c *Client) tlsKeepalive() error {
	svc, req := SvcIdentify, IdentifyRequest()
	switch {
	case c.Supports(SvcIdentify):
	case c.Supports(SvcStatus):
		svc, req = SvcStatus, StatusRequest(false)
	default:
		return errors.New("the server offers neither Identify nor Status")
	}
	select {
	case <-c.done:
		return c.Err()
	default:
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = c.call(ctx, req, svc)
	}()
	return nil
}

// Negotiated is the server's initiate response: the negotiated version,
// parameter CBBs and outstanding counts, and the services it supports.
func (c *Client) Negotiated() Initiate { return c.neg }

// Supports reports whether the server listed service bit n (a Svc
// constant, or one of the Bit constants) in its services supported.
func (c *Client) Supports(n int) bool { return c.neg.Supports(n) }

// Done is closed when the association ends.
func (c *Client) Done() <-chan struct{} { return c.done }

// Err is why the association ended.
func (c *Client) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Client) fail(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return
	}
	c.err = err
	for id, ch := range c.pending {
		ch <- reply{err: err}
		delete(c.pending, id)
	}
	if c.conclud != nil {
		c.conclud <- err
		c.conclud = nil
	}
	close(c.done)
	_ = c.t.c.Close()
}

func (c *Client) readLoop() {
	for {
		b, err := c.t.readTSDU()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				err = errors.New("the IED closed the connection")
			}
			c.fail(err)
			return
		}
		si, _, rest, err := parseSPDU(b)
		if err != nil {
			c.fail(err)
			return
		}
		switch si {
		case spduData:
			si2, _, user, err := parseSPDU(rest)
			if err != nil || si2 != spduData {
				c.fail(errors.New("session: a data SPDU without data transfer"))
				return
			}
			pdu, err := c.t.recvMMS(user)
			if err != nil {
				c.fail(err)
				return
			}
			c.dispatch(pdu)
		case spduDisconnect, spduAbort:
			c.fail(errors.New("the IED ended the association"))
			return
		default:
			c.fail(fmt.Errorf("session: unexpected SPDU %#x", si))
			return
		}
	}
}

func (c *Client) dispatch(pdu []byte) {
	e, _, err := Parse(pdu)
	if err != nil {
		c.fail(err)
		return
	}
	switch e.Tag {
	case TagConfirmedResponse:
		kids, err := e.Children()
		if err != nil || len(kids) < 2 {
			c.fail(errors.New("mms: a bad confirmed response"))
			return
		}
		id, _ := DecodeUint(kids[0].Val)
		c.deliver(uint32(id), reply{body: kids[1]})
	case TagConfirmedError:
		kids, _ := e.Children()
		if len(kids) == 0 {
			return
		}
		id, _ := DecodeUint(kids[0].Val)
		c.deliver(uint32(id), reply{err: decodeServiceError(e)})
	case TagReject:
		if id, ok, r := DecodeReject(e); ok && r.PDU == RejectConfirmedRequest {
			c.deliver(id, reply{err: r})
		}
	case TagUnconfirmed:
		kids, _ := e.Children()
		if len(kids) == 0 {
			return
		}
		switch {
		case kids[0].Context(UsvcInformationReport):
			if r, err := DecodeInformationReport(e); err == nil && c.onReport != nil {
				c.onReport(r)
			}
		case kids[0].Context(UsvcEventNotification):
			if n, err := DecodeEventNotification(e); err == nil && c.onEvent != nil {
				c.onEvent(n)
			}
		}
	case TagConcludeResponse, TagConcludeError:
		var err error
		if e.Tag == TagConcludeError {
			se, derr := DecodeServiceError(e.Val)
			if derr != nil {
				err = derr
			} else {
				err = &se
			}
		}
		c.mu.Lock()
		if c.conclud != nil {
			c.conclud <- err
			c.conclud = nil
		}
		c.mu.Unlock()
	}
}

func (c *Client) deliver(id uint32, r reply) {
	c.mu.Lock()
	ch := c.pending[id]
	delete(c.pending, id)
	c.mu.Unlock()
	if ch != nil {
		ch <- r
	}
}

// call sends a confirmed request and waits for its response.
func (c *Client) call(ctx context.Context, service []byte, want int) (Elem, error) {
	// At most the negotiated number of requests is outstanding at the
	// server (ISO 9506-1:2003 8.2.1.2.3).
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-ctx.Done():
		return Elem{}, ctx.Err()
	case <-c.done:
		return Elem{}, c.Err()
	}
	ch := make(chan reply, 1)
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return Elem{}, err
	}
	c.invoke++
	id := c.invoke
	c.pending[id] = ch
	c.mu.Unlock()
	if err := c.t.sendMMS(ctxMMS, ConfirmedRequest(id, service)); err != nil {
		c.fail(err)
		return Elem{}, err
	}
	select {
	case r := <-ch:
		if r.err != nil {
			return Elem{}, r.err
		}
		if r.body.Tag&0xc0 != 0x80 || r.body.Num != want {
			return Elem{}, fmt.Errorf("mms: response for service %d to a service %d request", r.body.Num, want)
		}
		return r.body, nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return Elem{}, ctx.Err()
	}
}

// Identify asks the server's vendor, model and revision.
func (c *Client) Identify(ctx context.Context) (Identity, error) {
	body, err := c.call(ctx, IdentifyRequest(), SvcIdentify)
	if err != nil {
		return Identity{}, err
	}
	return DecodeIdentity(body)
}

// Status asks the VMD's logical and physical status.
func (c *Client) Status(ctx context.Context, extended bool) (VMDStatus, error) {
	body, err := c.call(ctx, StatusRequest(extended), SvcStatus)
	if err != nil {
		return VMDStatus{}, err
	}
	return DecodeStatus(body)
}

// ReadWithSpec reads variables asking for the specification with the
// results, and returns both.
func (c *Client) ReadWithSpec(ctx context.Context, spec VariableSpec) (*VariableSpec, []AccessResult, error) {
	body, err := c.call(ctx, ReadRequestWithSpec(spec), SvcRead)
	if err != nil {
		return nil, nil, err
	}
	res, err := decodeReadResponse(body)
	if err != nil {
		return nil, nil, err
	}
	kids, _ := body.Children()
	for _, k := range kids {
		if k.Tag == 0xa0 {
			in, _, err := Parse(k.Val)
			if err != nil {
				return nil, nil, err
			}
			got, err := DecodeVariableSpec(in)
			if err != nil {
				return nil, nil, err
			}
			return &got, res, nil
		}
	}
	return nil, res, nil
}

// GetNameList lists every name of a class in a domain ("" for the VMD),
// following continuation.
func (c *Client) GetNameList(ctx context.Context, class int, domain string) ([]string, error) {
	var out []string
	after := ""
	for range 1000 {
		body, err := c.call(ctx, GetNameListRequest(class, domain, after), SvcGetNameList)
		if err != nil {
			return nil, err
		}
		names, more, err := decodeNameList(body)
		if err != nil {
			return nil, err
		}
		out = append(out, names...)
		if !more {
			return out, nil
		}
		after = names[len(names)-1]
	}
	return nil, errors.New("mms: the name list does not end")
}

// Read reads variables (or a named variable list).
func (c *Client) Read(ctx context.Context, spec VariableSpec) ([]AccessResult, error) {
	body, err := c.call(ctx, ReadRequest(spec), SvcRead)
	if err != nil {
		return nil, err
	}
	return decodeReadResponse(body)
}

// ReadOne reads one variable.
func (c *Client) ReadOne(ctx context.Context, n ObjectName) (Data, error) {
	res, err := c.Read(ctx, VariableSpec{Vars: []ObjectName{n}})
	if err != nil {
		return Data{}, err
	}
	if len(res) != 1 {
		return Data{}, fmt.Errorf("mms: %d results for one variable", len(res))
	}
	return res[0].Data, res[0].Err
}

// Write writes variables and returns one error (or nil) per variable.
func (c *Client) Write(ctx context.Context, names []ObjectName, values []Data) ([]error, error) {
	body, err := c.call(ctx, WriteRequest(VariableSpec{Vars: names}, values), SvcWrite)
	if err != nil {
		return nil, err
	}
	res, err := decodeWriteResponse(body)
	if err != nil {
		return nil, err
	}
	if len(res) != len(names) {
		return nil, fmt.Errorf("mms: %d write results for %d variables", len(res), len(names))
	}
	return res, nil
}

// WriteOne writes one variable.
func (c *Client) WriteOne(ctx context.Context, n ObjectName, v Data) error {
	res, err := c.Write(ctx, []ObjectName{n}, []Data{v})
	if err != nil {
		return err
	}
	return res[0]
}

// GetVariableAccessAttributes returns a variable's type.
func (c *Client) GetVariableAccessAttributes(ctx context.Context, n ObjectName) (TypeSpec, error) {
	body, err := c.call(ctx, GetVariableAccessAttributesRequest(n), SvcGetVariableAccessAttributes)
	if err != nil {
		return TypeSpec{}, err
	}
	return decodeVAAResponse(body)
}

// GetNamedVariableListAttributes returns a named variable list's members.
func (c *Client) GetNamedVariableListAttributes(ctx context.Context, n ObjectName) ([]ObjectName, error) {
	body, err := c.call(ctx, GetNamedVariableListAttributesRequest(n), SvcGetNamedVariableListAttributes)
	if err != nil {
		return nil, err
	}
	return decodeNVLAResponse(body)
}

// Conclude ends the association in order: MMS conclude, then the session
// finish carrying the ACSE release request. The connection is closed
// whatever happens.
func (c *Client) Conclude(ctx context.Context) error {
	ch := make(chan error, 1)
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return nil
	}
	c.conclud = ch
	c.mu.Unlock()
	if err := c.t.sendMMS(ctxMMS, T(TagConcludeRequest)); err != nil {
		c.fail(errors.New("the association was concluded"))
		return err
	}
	select {
	case err := <-ch:
		var se *ServiceError
		if errors.As(err, &se) {
			// A conclude-ErrorPDU: the server keeps the association
			// (ISO 9506-1:2003 8.4); the caller decides to close.
			return err
		}
		if err != nil {
			c.fail(errors.New("the association was concluded"))
			return err
		}
	case <-ctx.Done():
		c.fail(errors.New("the association was concluded"))
		return ctx.Err()
	}
	defer c.fail(errors.New("the association was concluded"))
	rlrq := pdv(ctxACSE, T(0x62, Int(0x80, 0)))
	if s := c.t.e2e; s != nil {
		// A signed ReleaseReq in the RLRQ (13.1.10, 15.3.5).
		req, _ := s.e.signed(0x30, s.e.token3(s.assoID))
		rlrq = pdv(ctxACSE, T(0x62, Int(0x80, 0), e2eExternal(s.pciE2E, req)))
	}
	return c.t.writeTSDU(spdu(spduFinish, sessParam(0xc1, rlrq)))
}

// Close drops the connection without concluding.
func (c *Client) Close() { c.fail(errors.New("the association was closed")) }
