package sv

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"time"
)

// Sync is the publisher's synchronisation state at a sampling instant
// (clause 9).
type Sync struct {
	// SmpSynch is 0 (internal), 1 (local) or 2 (global); publishers never
	// send more than 2 (C.3.4).
	SmpSynch uint8
	// GmIdentity is the PTP grandmaster identity in network order, sent
	// when OptFlds asks for it.
	GmIdentity [8]byte
	// TimeQuality is the time quality octet of refrTm.
	TimeQuality uint8
}

// Source gives the data set values of sample k, taken at at.
type Source interface {
	Sample(k uint64, at time.Time) ([]any, error)
}

// SourceFunc adapts a function to Source.
type SourceFunc func(k uint64, at time.Time) ([]any, error)

// Sample calls f.
func (f SourceFunc) Sample(k uint64, at time.Time) ([]any, error) { return f(k, at) }

// Clock gives the synchronisation state at an instant.
type Clock func(at time.Time) Sync

// Config is a publisher's control block and data set.
type Config struct {
	CB    MSVCB
	Src   net.HardwareAddr
	Types []Type // data set member types (Table 15)
	// NominalHz is the nominal frequency for SmpMod 0 (default 50).
	NominalHz float64
	// Simulate sets the S bit (Figure 3).
	Simulate bool
	// CountWrap is the smpCnt modulus; 0 means one second's worth of
	// samples (up to 65536), or 65536 when that is not a whole number
	// (F-1078).
	CountWrap int
	// FreeRunning keeps smpCnt counting on from the previous sample even
	// while synchronised, instead of restarting at each second.
	FreeRunning bool
	// Security, when set, gives the savPdu security element (IEC
	// 62351-6) for a frame formatted at the instant given.
	Security func(at time.Time) ([]byte, error)
}

// Publisher formats the SendMSVMessage frames of one MSVCB: a sample
// per sampling instant, noASDU of them per frame, oldest first (8.5.1).
type Publisher struct {
	c    Config
	sps  float64 // samples per second
	wrap int

	mu   sync.Mutex
	buf  []ASDU
	next int // free-running smpCnt
}

// NewPublisher checks the configuration.
func NewPublisher(c Config) (*Publisher, error) {
	if err := c.CB.Validate(); err != nil {
		return nil, err
	}
	if len(c.Src) != 6 || IsMulticast(c.Src) {
		return nil, errors.New("sv: the source MAC must be a unicast address (5.3.3.2)")
	}
	if _, err := SampleSize(c.Types); err != nil {
		return nil, err
	}
	if c.NominalHz == 0 {
		c.NominalHz = 50
	}
	if c.NominalHz < 0 || c.NominalHz > 1000 {
		return nil, errors.New("sv: nominal frequency out of range")
	}
	p := &Publisher{c: c}
	switch c.CB.SmpMod {
	case SmpPerPeriod:
		p.sps = float64(c.CB.SmpRate) * c.NominalHz
	case SmpPerSecond:
		p.sps = float64(c.CB.SmpRate)
	case SecPerSample:
		p.sps = 1 / float64(c.CB.SmpRate)
	}
	p.wrap = c.CountWrap
	if p.wrap == 0 {
		p.wrap = 65536
		if s := p.sps; s >= 1 && s <= 65536 && s == math.Trunc(s) {
			p.wrap = int(s)
		}
	}
	if p.wrap < 1 || p.wrap > 65536 {
		return nil, errors.New("sv: smpCnt wrap must be 1..65536")
	}
	return p, nil
}

// SamplesPerSecond is the sampling rate from SmpRate and SmpMod.
func (p *Publisher) SamplesPerSecond() float64 { return p.sps }

// Wrap is the smpCnt modulus.
func (p *Publisher) Wrap() int { return p.wrap }

// SampleTime is instant k of a schedule starting at start.
func (p *Publisher) SampleTime(start time.Time, k uint64) time.Time {
	return start.Add(time.Duration(math.Round(float64(k) * 1e9 / p.sps)))
}

// smpCnt of a sample at at. A synchronised publisher whose counter wraps
// once a second counts from 0 at the start of each second (the IEC
// 61869-9 use named in Table 14); otherwise the counter runs free and
// rolls over at the wrap.
func (p *Publisher) smpCnt(at time.Time, synch uint8) uint16 {
	c := p.next
	if synch != SynchInternal && !p.c.FreeRunning && float64(p.wrap) == p.sps {
		c = int(math.Round(float64(at.Nanosecond())*p.sps/1e9)) % p.wrap
	}
	p.next = (c + 1) % p.wrap
	return uint16(c)
}

// Push adds the sample taken at at and returns the frame once noASDU
// samples are held, else nil.
func (p *Publisher) Push(at time.Time, values []any, s Sync) ([]byte, error) {
	if s.SmpSynch > SynchGlobal {
		return nil, fmt.Errorf("sv: smpSynch %d is not sent (clause 9, C.3.4)", s.SmpSynch)
	}
	sample, err := EncodeSample(p.c.Types, values)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	cb := p.c.CB
	a := ASDU{SvID: cb.MsvID, SmpCnt: p.smpCnt(at, s.SmpSynch), ConfRev: cb.ConfRev, SmpSynch: s.SmpSynch, Sample: sample}
	if cb.OptFlds&OptDataSetName != 0 {
		d := cb.DatSet
		a.DatSet = &d
	}
	if cb.OptFlds&OptRefreshTime != 0 {
		t := TimestampOf(at, s.TimeQuality)
		a.RefrTm = &t
	}
	if cb.OptFlds&OptSampleRate != 0 {
		r := cb.SmpRate
		a.SmpRate = &r
	}
	if cb.OptFlds&OptSampleMode != 0 {
		m := cb.SmpMod
		a.SmpMod = &m
	}
	if cb.OptFlds&OptSynchSourceIdentity != 0 {
		g := s.GmIdentity
		a.GmIdentity = &g
	}
	p.buf = append(p.buf, a)
	if len(p.buf) < int(cb.NoASDU) {
		return nil, nil
	}
	pdu := &SavPDU{ASDUs: p.buf}
	p.buf = nil
	if p.c.Security != nil {
		if pdu.Security, err = p.c.Security(at); err != nil {
			return nil, err
		}
	}
	d := cb.DstAddress
	return Encode(Header{Dst: d.Addr, Src: p.c.Src, Tagged: true, Priority: d.Priority, VID: d.VID, APPID: d.APPID, Simulate: p.c.Simulate}, pdu)
}

// Generate formats count samples of the schedule starting at start
// (sample k at start + k/rate) and returns the frames.
func (p *Publisher) Generate(start time.Time, first uint64, count int, src Source, clock Clock) ([][]byte, error) {
	var out [][]byte
	for i := 0; i < count; i++ {
		k := first + uint64(i)
		at := p.SampleTime(start, k)
		f, err := p.take(k, at, src, clock)
		if err != nil {
			return out, err
		}
		if f != nil {
			out = append(out, f)
		}
	}
	return out, nil
}

func (p *Publisher) take(k uint64, at time.Time, src Source, clock Clock) ([]byte, error) {
	v, err := src.Sample(k, at)
	if err != nil {
		return nil, err
	}
	var s Sync
	if clock != nil {
		s = clock(at)
	}
	return p.Push(at, v, s)
}

// Run samples src on the schedule from start until ctx ends, and sends
// each frame. It returns ctx's error or the first failure.
func (p *Publisher) Run(ctx context.Context, start time.Time, src Source, clock Clock, send func([]byte) error) error {
	t := time.NewTimer(0)
	defer t.Stop()
	for k := uint64(0); ; k++ {
		at := p.SampleTime(start, k)
		if d := time.Until(at); d > 0 {
			t.Reset(d)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
			}
		} else if err := ctx.Err(); err != nil {
			return err
		}
		f, err := p.take(k, at, src, clock)
		if err != nil {
			return err
		}
		if f != nil {
			if err := send(f); err != nil {
				return err
			}
		}
	}
}
