package goose

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Source delivers Ethernet frames (destination MAC first).
type Source interface {
	// ReadFrame copies the next frame into buf and returns its length and
	// capture time. io.EOF ends a replay.
	ReadFrame(buf []byte) (int, time.Time, error)
	Close() error
}

// ErrNotSupported is returned by OpenInterface and OpenSendInterface
// where raw Ethernet is not built (every OS but Linux).
var ErrNotSupported = errors.New("capturing or sending GOOSE and sampled values on an interface needs Linux (AF_PACKET); use replay or record elsewhere")

// ---- pcap -------------------------------------------------------------------

// pcap file format (the classic libpcap format): a 24-octet header whose
// magic number gives the byte order and time stamp resolution, then per
// packet 16 octets of time stamp and lengths followed by the data.
const (
	pcapMagicMicro = 0xa1b2c3d4
	pcapMagicNano  = 0xa1b23c4d
	linkEthernet   = 1
)

type pcapSource struct {
	f        *os.File
	r        *bufio.Reader
	order    binary.ByteOrder
	nano     bool
	realtime bool
	first    time.Time
	started  time.Time
}

// OpenPcap replays frames from a pcap file of Ethernet frames. With
// realtime the frames are delivered at the pace of their time stamps,
// otherwise as fast as they are read.
func OpenPcap(path string, realtime bool) (Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	s := &pcapSource{f: f, r: bufio.NewReader(f), realtime: realtime}
	var h [24]byte
	if _, err := io.ReadFull(s.r, h[:]); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%s is not a pcap file: %w", path, err)
	}
	switch {
	case binary.LittleEndian.Uint32(h[:]) == pcapMagicMicro:
		s.order = binary.LittleEndian
	case binary.BigEndian.Uint32(h[:]) == pcapMagicMicro:
		s.order = binary.BigEndian
	case binary.LittleEndian.Uint32(h[:]) == pcapMagicNano:
		s.order, s.nano = binary.LittleEndian, true
	case binary.BigEndian.Uint32(h[:]) == pcapMagicNano:
		s.order, s.nano = binary.BigEndian, true
	default:
		_ = f.Close()
		return nil, fmt.Errorf("%s is not a pcap file (pcapng is not read; save as pcap)", path)
	}
	if lt := s.order.Uint32(h[20:]) & 0x0fffffff; lt != linkEthernet {
		_ = f.Close()
		return nil, fmt.Errorf("%s holds link type %d, not Ethernet", path, lt)
	}
	return s, nil
}

func (s *pcapSource) ReadFrame(buf []byte) (int, time.Time, error) {
	var h [16]byte
	if _, err := io.ReadFull(s.r, h[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, time.Time{}, errors.New("the pcap file ends inside a record header")
		}
		return 0, time.Time{}, err
	}
	sec, frac := s.order.Uint32(h[0:]), s.order.Uint32(h[4:])
	n := int(s.order.Uint32(h[8:]))
	if n > 262144 {
		return 0, time.Time{}, fmt.Errorf("a pcap record of %d octets", n)
	}
	ns := int64(frac) * 1000
	if s.nano {
		ns = int64(frac)
	}
	at := time.Unix(int64(sec), ns)
	data := make([]byte, n)
	if _, err := io.ReadFull(s.r, data); err != nil {
		return 0, time.Time{}, errors.New("the pcap file ends inside a record")
	}
	if s.realtime {
		if s.first.IsZero() {
			s.first, s.started = at, time.Now()
		} else if wait := at.Sub(s.first) - time.Since(s.started); wait > 0 {
			time.Sleep(wait)
		}
	}
	return copy(buf, data), at, nil
}

func (s *pcapSource) Close() error { return s.f.Close() }

// PcapWriter writes Ethernet frames to a pcap file (microsecond time
// stamps, little-endian), for recordings and tests.
type PcapWriter struct {
	w io.Writer
}

// NewPcapWriter writes the file header.
func NewPcapWriter(w io.Writer) (*PcapWriter, error) {
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h[0:], pcapMagicMicro)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], 65535)
	binary.LittleEndian.PutUint32(h[20:], linkEthernet)
	_, err := w.Write(h)
	return &PcapWriter{w: w}, err
}

// Write appends one frame.
func (p *PcapWriter) Write(at time.Time, frame []byte) error {
	h := make([]byte, 16)
	binary.LittleEndian.PutUint32(h[0:], uint32(at.Unix()))
	binary.LittleEndian.PutUint32(h[4:], uint32(at.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(h[8:], uint32(len(frame)))
	binary.LittleEndian.PutUint32(h[12:], uint32(len(frame)))
	if _, err := p.w.Write(h); err != nil {
		return err
	}
	_, err := p.w.Write(frame)
	return err
}
