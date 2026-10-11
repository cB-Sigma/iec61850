package goose

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

// Publication is a GOOSE control block to publish: its data set members
// are set through a Publisher and sent with the retransmission scheme of
// IEC 61850-8-1 18.1.2.5. Validate checks it and fills in the defaults.
type Publication struct {
	ID      string
	GoCBRef string
	DataSet string
	// GoID defaults to the control block reference (8-1 18.1.1.1.1).
	GoID   string
	APPID  APPID
	DstMAC string
	// SrcMAC defaults to the interface's address.
	SrcMAC string
	// VLANID and Priority of the 802.1Q tag every frame carries (8-1
	// C.2.2); VLAN 0 by default (Table C.1) and priority 4.
	VLANID   *int
	Priority *int
	ConfRev  uint32
	// MinTime is the first repetition after a change, MaxTime the
	// repetition in stable conditions (8-1 Figure 8; at most 60 s).
	MinTime    time.Duration
	MaxTime    time.Duration
	Simulation bool
	NdsCom     bool
	Members    []PubMember
	// UDPDst sends the publication as routable GOOSE (8-1 Annex J,
	// unsecured) to this IPv4 address ("ip" or "ip:port", port 102 by
	// default) instead of on Ethernet; TTL (32..254, default 32) and
	// DSCP (0..63, default 46) set the IP header (J.3.3).
	UDPDst string
	TTL    *int
	DSCP   *int
	// SecurityEnabled sends every message with the IEC 62351-6
	// AuthenticationValue and MAC (Layer 2 extension, or a secured
	// routable SPDU) under the key held for the publication's APPID and
	// data set (tGSEControl securityEnabled, 9.2.1).
	SecurityEnabled bool

	dst, src  net.HardwareAddr
	vlan      int
	prio      int
	udpDst    *net.UDPAddr
	ttl, dscp int
}

// PubMember is a published data set member and its IEC 61850-7-2 basic
// type (boolean, int8/16/32/64, int8u/16u/32u, float32, enum, dbpos,
// quality, visstring, timestamp, octets).
type PubMember struct {
	Name string
	Type string
}

// memberTypes are the basic types a published member may have.
var memberTypes = map[string]bool{
	"boolean": true, "int8": true, "int16": true, "int32": true, "int64": true, "int8u": true, "int16u": true, "int32u": true,
	"float32": true, "enum": true, "dbpos": true, "quality": true, "visstring": true, "timestamp": true, "octets": true,
}

// Publisher defaults.
const (
	defaultPriority = 4
	defaultMinTime  = 10 * time.Millisecond
	defaultMaxTime  = time.Second
	maxMaxTime      = 60 * time.Second // 8-1 18.1.1.1.1 MaxTime
	maxRefLen       = 129              // 8-1 18.1.2.5.2
	// pubTimeQuality: the time accuracy is not known ("unspecified",
	// 8-1 Table 36); the clock is taken as synchronised.
	pubTimeQuality = 0x1f
)

// Validate checks the publication and fills in its defaults.
func (p *Publication) Validate() error {
	if p.ID == "" {
		return errors.New("needs an id")
	}
	if p.GoCBRef == "" || p.DataSet == "" {
		return errors.New("needs gocbRef and dataSet")
	}
	if p.GoID == "" {
		p.GoID = p.GoCBRef
	}
	for _, s := range []string{p.GoCBRef, p.DataSet, p.GoID} {
		if len(s) > maxRefLen {
			return fmt.Errorf("%q is longer than %d octets", s, maxRefLen)
		}
	}
	if !p.APPID.set() {
		return errors.New("needs an appId")
	}
	// 0x0000 means "not configured"; type 1 is 0x0001-0x3FFF, type 1A
	// (trip) 0x8000-0xBFFF (8-1 C.2.5).
	if a := p.APPID.value(); a == 0 || (a > 0x3fff && a < 0x8000) || a > 0xbfff {
		return fmt.Errorf("appId %s is outside the GOOSE ranges 0x0001-0x3FFF and 0x8000-0xBFFF", p.APPID)
	}
	var err error
	if p.dst, err = ParseMAC(p.DstMAC); err != nil || p.dst == nil || p.dst[0]&1 == 0 {
		return fmt.Errorf("dstMac %q is not a multicast MAC address", p.DstMAC)
	}
	if p.src, err = ParseMAC(p.SrcMAC); err != nil || (p.src != nil && p.src[0]&1 != 0) {
		return fmt.Errorf("srcMac %q is not a unicast MAC address", p.SrcMAC)
	}
	p.vlan, p.prio = 0, defaultPriority
	if p.VLANID != nil {
		if *p.VLANID < 0 || *p.VLANID > 4095 {
			return fmt.Errorf("vlanId %d is not 0..4095", *p.VLANID)
		}
		p.vlan = *p.VLANID
	}
	if p.Priority != nil {
		if *p.Priority < 0 || *p.Priority > 7 {
			return fmt.Errorf("priority %d is not 0..7", *p.Priority)
		}
		p.prio = *p.Priority
	}
	if p.UDPDst != "" {
		if p.udpDst, err = udpTarget(p.UDPDst); err != nil {
			return err
		}
	}
	p.ttl, p.dscp = defaultTTL, defaultDSCP
	if p.TTL != nil {
		// At least 32 so the packets can be routed; 255 is not allowed.
		if *p.TTL < 32 || *p.TTL > 254 {
			return fmt.Errorf("ttl %d is not 32..254", *p.TTL)
		}
		p.ttl = *p.TTL
	}
	if p.DSCP != nil {
		if *p.DSCP < 0 || *p.DSCP > 63 {
			return fmt.Errorf("dscp %d is not 0..63", *p.DSCP)
		}
		p.dscp = *p.DSCP
	}
	// A control block of confRev 0 cannot be enabled (7-2 Table 87).
	if p.ConfRev == 0 {
		return errors.New("confRev 0 is kept for control blocks never configured")
	}
	if p.MinTime <= 0 {
		p.MinTime = defaultMinTime
	}
	if p.MaxTime <= 0 {
		p.MaxTime = defaultMaxTime
	}
	if p.MaxTime > maxMaxTime || p.MinTime > p.MaxTime {
		return errors.New("needs minTime <= maxTime <= 60s")
	}
	if len(p.Members) == 0 {
		return errors.New("needs members")
	}
	names := map[string]bool{}
	for _, m := range p.Members {
		if m.Name == "" || names[m.Name] || m.Name == "status" {
			return errors.New("members need unique names other than status")
		}
		names[m.Name] = true
		if !memberTypes[m.Type] {
			return fmt.Errorf("member %s has type %q, not one of boolean, int8/16/32/64, int8u/16u/32u, float32, enum, dbpos, quality, visstring, timestamp, octets", m.Name, m.Type)
		}
	}
	return nil
}

// zeroValue is a member's initial value (a local issue, 7-2 Table 87).
func zeroValue(typ string) mms.Data {
	d, _ := memberValue(typ, nil)
	return d
}

// memberValue converts a JSON value to a member's MMS data (nil gives
// the type's initial value).
func memberValue(typ string, v any) (mms.Data, error) {
	num := func(lo, hi float64) (float64, error) {
		if v == nil {
			return 0, nil
		}
		f, ok := v.(float64)
		if !ok || f != math.Trunc(f) || f < lo || f > hi {
			return 0, fmt.Errorf("%v is not an integer in %v..%v", v, lo, hi)
		}
		return f, nil
	}
	switch typ {
	case "boolean":
		b, ok := v.(bool)
		if !ok && v != nil {
			return mms.Data{}, fmt.Errorf("%v is not a boolean", v)
		}
		return mms.Boolean(b), nil
	case "int8", "enum":
		f, err := num(math.MinInt8, math.MaxInt8)
		return mms.Integer(int64(f)), err
	case "int16":
		f, err := num(math.MinInt16, math.MaxInt16)
		return mms.Integer(int64(f)), err
	case "int32":
		f, err := num(math.MinInt32, math.MaxInt32)
		return mms.Integer(int64(f)), err
	case "int64":
		f, err := num(-(1 << 53), 1<<53)
		return mms.Integer(int64(f)), err
	case "int8u":
		f, err := num(0, math.MaxUint8)
		return mms.Unsigned(uint64(f)), err
	case "int16u":
		f, err := num(0, math.MaxUint16)
		return mms.Unsigned(uint64(f)), err
	case "int32u":
		f, err := num(0, math.MaxUint32)
		return mms.Unsigned(uint64(f)), err
	case "float32":
		f, ok := v.(float64)
		if !ok && v != nil {
			return mms.Data{}, fmt.Errorf("%v is not a number", v)
		}
		return mms.Float32(f), nil
	case "dbpos":
		b := mms.NewBitString(2)
		switch v {
		case nil, "intermediate":
		case "off":
			b.Set(1, true)
		case "on":
			b.Set(0, true)
		case "bad":
			b.Set(0, true)
			b.Set(1, true)
		default:
			return mms.Data{}, fmt.Errorf("%v is not intermediate, off, on or bad", v)
		}
		return mms.Bits(b), nil
	case "quality":
		return qualityValue(v)
	case "visstring":
		s, ok := v.(string)
		if (!ok && v != nil) || len(s) > 255 {
			return mms.Data{}, fmt.Errorf("%v is not a string of up to 255 characters", v)
		}
		return mms.Visible(s), nil
	case "octets":
		s, ok := v.(string)
		if !ok && v != nil {
			return mms.Data{}, fmt.Errorf("%v is not a hexadecimal string", v)
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return mms.Data{}, fmt.Errorf("%q is not a hexadecimal string", s)
		}
		return mms.Octets(b), nil
	case "timestamp":
		var t time.Time
		if v != nil {
			s, ok := v.(string)
			var err error
			if t, err = time.Parse(time.RFC3339Nano, s); !ok || err != nil {
				return mms.Data{}, fmt.Errorf("%v is not an RFC 3339 time", v)
			}
		}
		d := mms.Timestamp(t)
		d.Time.Quality = pubTimeQuality
		return d, nil
	}
	return mms.Data{}, fmt.Errorf("unknown type %s", typ)
}

// qualityValue builds the 13-bit quality (8-1 Table 44) from a validity
// name or an object {validity, source, test, operatorBlocked}.
func qualityValue(v any) (mms.Data, error) {
	b := mms.NewBitString(13)
	m, _ := v.(map[string]any)
	validity, _ := v.(string)
	if m != nil {
		validity, _ = m["validity"].(string)
		if src, _ := m["source"].(string); src == "substituted" {
			b.Set(10, true)
		}
		if t, _ := m["test"].(bool); t {
			b.Set(11, true)
		}
		if o, _ := m["operatorBlocked"].(bool); o {
			b.Set(12, true)
		}
	} else if v != nil && validity == "" {
		return mms.Data{}, fmt.Errorf("%v is not a quality", v)
	}
	switch validity {
	case "", "good":
	case "invalid":
		b.Set(1, true)
	case "reserved":
		b.Set(0, true)
	case "questionable":
		b.Set(0, true)
		b.Set(1, true)
	default:
		return mms.Data{}, fmt.Errorf("validity %q is not good, invalid, reserved or questionable", validity)
	}
	return mms.Bits(b), nil
}

// Publisher is the state machine of one GOOSE control block (8-1 Figure
// 10): enabling sends the current values with stNum 1 and sqNum 0; a
// change of value increments stNum and sends at once with sqNum 0; then
// the message is repeated after MinTime, twice that, and so on, doubling
// up to MaxTime, with sqNum incremented each time (both counters skip 0
// when they wrap). Each message's timeAllowedtoLive is twice the time to
// the next one, so one lost repetition is not reported as lost
// communication. It does no I/O: the caller sends the frames it returns.
type Publisher struct {
	mu       sync.Mutex
	cfg      *Publication
	values   []mms.Data
	enabled  bool
	stNum    uint32
	sqNum    uint32
	t        time.Time
	interval time.Duration
	nextAt   time.Time
}

// NewPublisher makes a disabled publisher with the members' initial
// values.
func NewPublisher(p *Publication) *Publisher {
	v := make([]mms.Data, len(p.Members))
	for i, m := range p.Members {
		v[i] = zeroValue(m.Type)
	}
	return &Publisher{cfg: p, values: v}
}

// Enable starts publishing (GoEna true) and returns the first frame.
func (p *Publisher) Enable(now time.Time) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = true
	p.stNum, p.sqNum, p.t = 1, 0, now
	p.interval = p.cfg.MinTime
	return p.frame(now)
}

// Disable stops publishing (GoEna false).
func (p *Publisher) Disable() {
	p.mu.Lock()
	p.enabled = false
	p.mu.Unlock()
}

// Set applies new member values (by member name) and, when one of them
// changed, returns the frame of the new state. Unknown members and
// values of the wrong type are refused and nothing changes.
func (p *Publisher) Set(values map[string]any, now time.Time) ([]byte, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := append([]mms.Data(nil), p.values...)
	for name, v := range values {
		i := -1
		for k, m := range p.cfg.Members {
			if m.Name == name {
				i = k
			}
		}
		if i < 0 {
			return nil, false, fmt.Errorf("the data set has no member %s", name)
		}
		d, err := memberValue(p.cfg.Members[i].Type, v)
		if err != nil {
			return nil, false, fmt.Errorf("member %s: %w", name, err)
		}
		next[i] = d
	}
	changed := false
	for i := range next {
		if string(next[i].Encode()) != string(p.values[i].Encode()) {
			changed = true
		}
	}
	p.values = next
	if !changed || !p.enabled {
		return nil, changed, nil
	}
	p.stNum, p.sqNum, p.t = nextCount(p.stNum), 0, now
	p.interval = p.cfg.MinTime
	return p.frame(now), true, nil
}

// Due returns the retransmission frame when its time has come.
func (p *Publisher) Due(now time.Time) ([]byte, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.enabled || now.Before(p.nextAt) {
		return nil, false
	}
	p.sqNum = nextCount(p.sqNum)
	p.interval = min(2*p.interval, p.cfg.MaxTime)
	return p.frame(now), true
}

// NextAt is when the next retransmission is due (zero when disabled).
func (p *Publisher) NextAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.enabled {
		return time.Time{}
	}
	return p.nextAt
}

// State reports stNum and sqNum of the last frame.
func (p *Publisher) State() (stNum, sqNum uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stNum, p.sqNum
}

// frame encodes the current message and schedules the next one; the
// caller holds mu.
func (p *Publisher) frame(now time.Time) []byte {
	p.nextAt = now.Add(p.interval)
	c := p.cfg
	src := c.src
	if src == nil {
		src = make(net.HardwareAddr, 6) // recorded frames without srcMac
	}
	return EncodeGOOSE(Frame{Dst: c.dst, Src: src, VLAN: c.vlan, Priority: c.prio, APPID: c.APPID.value(), Simulated: c.Simulation,
		GOOSE: &GOOSE{GoCBRef: c.GoCBRef, TAL: 2 * p.interval, DatSet: c.DataSet, GoID: c.GoID, T: p.t, TQuality: pubTimeQuality,
			StNum: p.stNum, SqNum: p.sqNum, Simulation: c.Simulation, ConfRev: c.ConfRev, NdsCom: c.NdsCom,
			AllData: append([]mms.Data(nil), p.values...)}})
}

// nextCount is the counter after n, skipping 0 on overflow.
func nextCount(n uint32) uint32 { return next(n) }

// Sink sends Ethernet frames (destination MAC first, no FCS).
type Sink interface {
	WriteFrame(frame []byte) error
	Close() error
}

type pcapSink struct {
	mu sync.Mutex
	f  *os.File
	w  *PcapWriter
}

// CreatePcapSink records published frames in a pcap file instead of
// sending them (any OS).
func CreatePcapSink(path string) (Sink, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w, err := NewPcapWriter(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &pcapSink{f: f, w: w}, nil
}

func (s *pcapSink) WriteFrame(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(time.Now(), b)
}

func (s *pcapSink) Close() error { return s.f.Close() }
