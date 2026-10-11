package goose

// Publishing for servers: an IEC 61850 server publishes GOOSE for its
// data sets with the publisher state machine (8-1 Figure 10), the sinks and
// the IEC 62351-6 security of this package.

import (
	"fmt"
	"sync"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

// Prepare checks a publication and fills its derived fields (addresses,
// tag, source MAC); call it before NewPublisher.
func (p *Publication) Prepare() error { return p.Validate() }

// SetSource sets the source MAC when the publication names none.
func (p *Publication) SetSource(mac []byte) {
	if p.src == nil {
		p.src = append([]byte(nil), mac...)
	}
}

// SetData applies new member values given as MMS data (by member name);
// when one changed it returns the frame of the new state. Values of
// another type than the member's are refused.
func (p *Publisher) SetData(values map[string]mms.Data, now time.Time) ([]byte, bool, error) {
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
		if v.Kind != next[i].Kind {
			return nil, false, fmt.Errorf("member %s: %s is not a %s", name, v.Kind, p.cfg.Members[i].Type)
		}
		next[i] = v
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

// SecureSink adds the IEC 62351-6 Layer 2 extension to each frame with
// the key the store holds for the APPID and data set (a sink for
// any publisher; Secured counts the frames).
type SecureSink struct {
	Sink
	Keys    *KeyStore
	APPID   uint16
	DataSet string
	OnError func(error)

	mu      sync.Mutex
	Secured int
}

// WriteFrame secures and writes one frame.
func (s *SecureSink) WriteFrame(b []byte) error {
	now := time.Now()
	cur, next, _ := s.Keys.Current(s.APPID, s.DataSet, now)
	if cur == nil {
		err := fmt.Errorf("no IEC 62351-6 key is valid for APPID 0x%04X and data set %s", s.APPID, s.DataSet)
		if s.OnError != nil {
			s.OnError(err)
		}
		return err
	}
	tock, ttnk := s.Keys.AuthFields(cur, next, now)
	out, err := SecureL2(b, cur, tock, ttnk, nil)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.Secured++
	s.mu.Unlock()
	return s.Sink.WriteFrame(out)
}

// Close leaves the underlying sink to its owner.
func (s *SecureSink) Close() error { return nil }

// Value is the APPID (0 when not set).
func (a APPID) Value() uint16 { return a.value() }
