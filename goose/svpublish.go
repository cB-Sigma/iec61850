package goose

// Secured sampled values publishing (IEC 62351-6 6.2.2.2, 8.2): SVStream
// frames samples with the IEC 61850-9-2 publisher of package sv, adding
// the savPdu security timestamp
// and, when Secure, the Layer 2 extension or a secured routable SPDU. It
// is meant for simulators, merging units and tests.

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	svcodec "github.com/cB-Sigma/iec61850/goose/sv"
	"github.com/cB-Sigma/iec61850/mms"
)

// SVStream is one published SV stream (one ASDU per frame).
type SVStream struct {
	Dst, Src       net.HardwareAddr
	VLAN, Priority int
	APPID          uint16
	SvID, DataSet  string
	ConfRev        uint32
	// SmpRate is samples per nominal period (smpMod SmpPerPeriod, the
	// IEC 61850-9-2 default); NominalHz the nominal frequency. smpCnt
	// wraps at SmpRate * NominalHz. The first frame fixes the number of
	// samples; VLAN < 0 sends VID 0 with priority 4 (9-2 Table 7).
	SmpRate   int
	NominalHz int
	SmpSynch  int
	Simulated bool
	// Keys and Secure: the key for APPID and DataSet secures each frame.
	Keys   *KeyStore
	Secure bool

	mu       sync.Mutex
	pub      *svcodec.Publisher
	members  int
	lastTick uint64 // last security timestamp in 2^-24 s units
}

// tick is t in the IEC 61850-8-1 time stamp resolution (2^-24 s).
func tick(t time.Time) uint64 {
	return uint64(t.Unix())<<24 | uint64(t.Nanosecond())<<24/1_000_000_000
}

// fromTick rounds up so that encoding gives the same tick back.
func fromTick(v uint64) time.Time {
	ns := ((v&0xffffff)*1_000_000_000 + (1<<24 - 1)) >> 24
	return time.Unix(int64(v>>24), int64(ns)).UTC()
}

// securityTime is now, moved on by one time stamp unit when it would not
// be later than the last one sent (6.2.2.3.2 needs strictly increasing
// values; F-823).
func (s *SVStream) securityTime(now time.Time) time.Time {
	t := tick(now)
	if t <= s.lastTick {
		t = s.lastTick + 1
	}
	s.lastTick = t
	return fromTick(t)
}

// publisher is the stream's IEC 61850-9-2 publisher (package sv) for n
// INT32 value / quality pairs, made on the first frame: one ASDU per
// frame, smpRate (and datSet when set) sent, smpCnt free-running with a
// wrap of SmpRate x NominalHz, and the savPdu security timestamp.
func (s *SVStream) publisher(n int) (*svcodec.Publisher, error) {
	if s.pub != nil {
		if n != s.members {
			return nil, fmt.Errorf("the stream's data set has %d samples, not %d", s.members, n)
		}
		return s.pub, nil
	}
	if s.SmpRate <= 0 || s.SmpRate > 65535 || s.NominalHz <= 0 {
		return nil, errors.New("an SV stream needs smpRate and the nominal frequency")
	}
	if s.VLAN > 4095 || s.Priority < 0 || s.Priority > 7 {
		return nil, errors.New("an SV stream needs a VLAN of 0..4095 and a priority of 0..7")
	}
	opt := svcodec.OptSampleRate
	ds := s.DataSet
	if ds != "" {
		opt |= svcodec.OptDataSetName
	} else {
		ds = s.SvID // the MSVCB needs a DatSet; it is not sent
	}
	// IEC 61850-9-2 5.3.3.3: a publisher always tags; without a VLAN the
	// Table 7 defaults (VID 0, priority 4) apply.
	vlan, prio := s.VLAN, s.Priority
	if vlan < 0 {
		vlan, prio = svcodec.DefaultVID, svcodec.DefaultPriority
	}
	types := make([]svcodec.Type, 0, 2*n)
	for range n {
		types = append(types, svcodec.Int32, svcodec.QualityType)
	}
	p, err := svcodec.NewPublisher(svcodec.Config{
		CB: svcodec.MSVCB{MsvID: s.SvID, DatSet: ds, ConfRev: s.ConfRev, SmpRate: uint16(s.SmpRate), SmpMod: svcodec.SmpPerPeriod,
			OptFlds: opt, NoASDU: 1, DstAddress: svcodec.PhyComAddr{Addr: s.Dst, Priority: uint8(prio), VID: uint16(vlan), APPID: s.APPID}},
		Src: s.Src, Types: types, NominalHz: float64(s.NominalHz), Simulate: s.Simulated, FreeRunning: true,
		Security: func(at time.Time) ([]byte, error) {
			return mms.T(0xa1, mms.T(0xa0, mms.T(0x80, mms.UTCTime{T: s.securityTime(at), Quality: 0x0a}.Encode()))), nil
		},
	})
	if err != nil {
		return nil, err
	}
	s.pub, s.members = p, n
	return p, nil
}

// next formats the next frame of the stream (tagged, unsecured).
func (s *SVStream) next(samples []Sample, now time.Time) ([]byte, error) {
	p, err := s.publisher(len(samples))
	if err != nil {
		return nil, err
	}
	if s.SmpSynch < 0 || s.SmpSynch > 255 {
		return nil, fmt.Errorf("smpSynch %d", s.SmpSynch)
	}
	v := make([]any, 0, 2*len(samples))
	for _, x := range samples {
		v = append(v, int64(x.Value), svcodec.Quality(x.Quality))
	}
	return p.Push(now, v, svcodec.Sync{SmpSynch: uint8(s.SmpSynch)})
}

func (s *SVStream) key(now time.Time) (*SecKey, uint32, int64, error) {
	if s.Keys == nil {
		return nil, 0, 0, errors.New("a secured SV stream needs keys")
	}
	cur, next, _ := s.Keys.Current(s.APPID, s.DataSet, now)
	if cur == nil {
		return nil, 0, 0, errors.New("no key is valid for the SV stream")
	}
	tock, ttnk := s.Keys.AuthFields(cur, next, now)
	return cur, tock, ttnk, nil
}

// Frame builds the next Ethernet frame of the stream.
func (s *SVStream) Frame(samples []Sample, now time.Time) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.next(samples, now)
	if err != nil {
		return nil, err
	}
	if !s.Secure {
		return b, nil
	}
	k, tock, ttnk, err := s.key(now)
	if err != nil {
		return nil, err
	}
	return SecureL2(b, k, tock, ttnk, nil)
}

// Routable builds the next routable SV SPDU (8-1 Annex J, SI A2) with
// SPDU number num, secured when Secure.
func (s *SVStream) Routable(samples []Sample, now time.Time, num uint32) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.next(samples, now)
	if err != nil {
		return nil, err
	}
	h, err := svcodec.DecodeHeader(b)
	if err != nil {
		return nil, err
	}
	p := SPDU{SI: SISV, Number: num, Version: SessionVersion,
		Payloads: []Payload{{Tag: PayloadSV, Simulation: s.Simulated, APPID: s.APPID, APDU: h.APDU}}}
	if !s.Secure {
		return EncodeRoutable(p)
	}
	k, tock, ttnk, err := s.key(now)
	if err != nil {
		return nil, err
	}
	return SealRoutable(p, k, tock, ttnk, nil)
}
