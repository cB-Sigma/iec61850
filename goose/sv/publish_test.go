package sv

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

var src = net.HardwareAddr{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}

// leSource gives the 9-2 LE data set: eight INT32 values with good
// quality, value k for every channel.
var leSource = SourceFunc(func(k uint64, _ time.Time) ([]any, error) {
	v := make([]any, 0, 16)
	for i := 0; i < 8; i++ {
		v = append(v, int64(k%1000), Quality(0))
	}
	return v, nil
})

func synced(at time.Time) Sync { return Sync{SmpSynch: SynchGlobal, TimeQuality: 0x0A} }

func newPub(t *testing.T, mod func(*Config)) *Publisher {
	t.Helper()
	c := Config{CB: testCB(), Src: src, Types: LE}
	if mod != nil {
		mod(&c)
	}
	p, err := NewPublisher(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func decodeAll(t *testing.T, frames [][]byte) []ASDU {
	t.Helper()
	var out []ASDU
	for _, b := range frames {
		f, err := Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, f.PDU.ASDUs...)
	}
	return out
}

// Covers: SIG-IPE-2097
func TestPublisherScheduleAndCount(t *testing.T) {
	// 80 samples per period at 50 Hz: 4000 per second, 250 µs apart;
	// synchronised, smpCnt runs 0..3999 from the start of each second.
	p := newPub(t, nil)
	if p.SamplesPerSecond() != 4000 || p.Wrap() != 4000 {
		t.Fatalf("rate %v wrap %d", p.SamplesPerSecond(), p.Wrap())
	}
	start := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	if d := p.SampleTime(start, 1).Sub(start); d != 250*time.Microsecond {
		t.Errorf("period %v", d)
	}
	frames, err := p.Generate(start, 0, 4001, leSource, synced)
	if err != nil || len(frames) != 4001 {
		t.Fatalf("%d frames, %v", len(frames), err)
	}
	as := decodeAll(t, frames)
	for i, a := range as {
		if int(a.SmpCnt) != i%4000 {
			t.Fatalf("sample %d smpCnt %d", i, a.SmpCnt)
		}
	}
	// 60 Hz: 4800 per second (208.33 µs); the count stays aligned.
	p = newPub(t, func(c *Config) { c.NominalHz = 60 })
	frames, _ = p.Generate(start, 0, 4801, leSource, synced)
	for i, a := range decodeAll(t, frames) {
		if int(a.SmpCnt) != i%4800 {
			t.Fatalf("60 Hz sample %d smpCnt %d", i, a.SmpCnt)
		}
	}
	// Not synchronised: the counter runs free from 0 whatever the time,
	// and rolls over at the wrap.
	p = newPub(t, func(c *Config) { c.CB.SmpMod, c.CB.SmpRate = SmpPerSecond, 1000 })
	frames, _ = p.Generate(start.Add(123*time.Millisecond), 0, 1002, leSource, nil)
	as = decodeAll(t, frames)
	if as[0].SmpCnt != 0 || as[999].SmpCnt != 999 || as[1000].SmpCnt != 0 || as[0].SmpSynch != 0 {
		t.Errorf("free-running counts %d %d %d", as[0].SmpCnt, as[999].SmpCnt, as[1000].SmpCnt)
	}
	// Seconds per sample: 65536 wrap; explicit wrap honoured.
	if p = newPub(t, func(c *Config) { c.CB.SmpMod, c.CB.SmpRate = SecPerSample, 2 }); p.Wrap() != 65536 || p.SampleTime(start, 1).Sub(start) != 2*time.Second {
		t.Errorf("seconds per sample: wrap %d", p.Wrap())
	}
	// FreeRunning: synchronised but counting on from 0.
	p = newPub(t, func(c *Config) { c.FreeRunning = true })
	frames, _ = p.Generate(start.Add(123*time.Millisecond), 0, 3, leSource, synced)
	if as = decodeAll(t, frames); as[0].SmpCnt != 0 || as[2].SmpCnt != 2 {
		t.Errorf("free-running while synchronised: %d %d", as[0].SmpCnt, as[2].SmpCnt)
	}
	p = newPub(t, func(c *Config) { c.CountWrap = 10 })
	frames, _ = p.Generate(start, 0, 11, leSource, nil)
	if as = decodeAll(t, frames); as[10].SmpCnt != 0 {
		t.Errorf("wrap 10: %d", as[10].SmpCnt)
	}
}

// Covers: SIG-IPE-2096, SIG-IPE-2081
func TestPublisherConcatenation(t *testing.T) {
	p := newPub(t, func(c *Config) { c.CB.NoASDU = 4 })
	start := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	frames, err := p.Generate(start, 0, 10, leSource, synced)
	if err != nil || len(frames) != 2 {
		t.Fatalf("%d frames, %v", len(frames), err)
	}
	for i, b := range frames {
		f, err := Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		// 5.3.3.3, Table 7: always tagged, priority 4, VID 0.
		if !f.Tagged || f.Priority != 4 || f.VID != 0 || f.APPID != 0x4000 || f.Simulate || f.Security != 0 || f.Reserved != 0 {
			t.Errorf("frame %d header %+v", i, f.Header)
		}
		if len(f.PDU.ASDUs) != 4 {
			t.Fatalf("frame %d holds %d ASDUs", i, len(f.PDU.ASDUs))
		}
		for j, a := range f.PDU.ASDUs {
			if int(a.SmpCnt) != i*4+j {
				t.Errorf("frame %d ASDU %d smpCnt %d: oldest first", i, j, a.SmpCnt)
			}
		}
	}
	p = newPub(t, func(c *Config) { c.Simulate = true; c.CB.DstAddress.Priority, c.CB.DstAddress.VID = 6, 5 })
	frames, _ = p.Generate(start, 0, 1, leSource, nil)
	if f, _ := Decode(frames[0]); !f.Simulate || f.Priority != 6 || f.VID != 5 {
		t.Errorf("configured header %+v", f.Header)
	}
}

// Covers: SIG-IPE-2098, SIG-IPE-2092
func TestPublisherOptionalFieldsAndSynch(t *testing.T) {
	gm := [8]byte{0, 0x1B, 0x19, 0xFF, 0xFE, 0, 0, 1}
	clock := func(at time.Time) Sync { return Sync{SmpSynch: SynchGlobal, GmIdentity: gm, TimeQuality: 0x0A} }
	p := newPub(t, func(c *Config) { c.CB.OptFlds = 0x7F })
	start := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	frames, err := p.Generate(start, 0, 2, leSource, clock)
	if err != nil {
		t.Fatal(err)
	}
	as := decodeAll(t, frames)
	a := as[1]
	if a.DatSet == nil || *a.DatSet != testCB().DatSet || a.SmpRate == nil || *a.SmpRate != 80 || a.SmpMod == nil || *a.SmpMod != SmpPerPeriod ||
		a.GmIdentity == nil || *a.GmIdentity != gm || a.RefrTm == nil || a.RefrTm.Time().Sub(start.Add(250*time.Microsecond)).Abs() > 100*time.Nanosecond || a.RefrTm.Quality != 0x0A || a.SmpSynch != 2 {
		t.Errorf("ASDU %+v", a)
	}
	v, err := DecodeSample(LE, a.Sample)
	if err != nil || v[0] != int64(1) || v[1] != Quality(0) {
		t.Errorf("sample %v %v", v, err)
	}
	// None of the options: only the mandatory components.
	p = newPub(t, nil)
	frames, _ = p.Generate(start, 0, 1, leSource, clock)
	if a = decodeAll(t, frames)[0]; a.DatSet != nil || a.SmpRate != nil || a.SmpMod != nil || a.GmIdentity != nil || a.RefrTm != nil {
		t.Errorf("optional components sent: %+v", a)
	}
	// Clause 9, C.3.4: values above 2 are not sent.
	if _, err := p.Push(start, mustLE(), Sync{SmpSynch: 5}); err == nil {
		t.Error("smpSynch 5 was sent")
	}
	// C.3.5: the formerly reserved validity is not sent.
	bad := mustLE()
	bad[1] = Quality(1)
	if _, err := p.Push(start, bad, Sync{}); err == nil {
		t.Error("reserved validity was sent")
	}
	// The security element comes from the IEC 62351-6 layer.
	p = newPub(t, func(c *Config) {
		c.Security = func(time.Time) ([]byte, error) { return []byte{0xA1, 0x02, 0xA0, 0x00}, nil }
	})
	frames, _ = p.Generate(start, 0, 1, leSource, nil)
	if f, err := Decode(frames[0]); err != nil || len(f.PDU.Security) != 4 {
		t.Errorf("security element: %v", err)
	}
}

func mustLE() []any {
	v, _ := leSource(0, time.Time{})
	return v
}

// Covers: SIG-IPE-2093
func TestPublisherRefusesBadConfig(t *testing.T) {
	for name, mod := range map[string]func(*Config){
		"multicast source": func(c *Config) { c.Src = net.HardwareAddr{1, 0, 0, 0, 0, 1} },
		"bad CB":           func(c *Config) { c.CB.DstAddress.APPID = 1 },
		"bad type":         func(c *Config) { c.Types = []Type{99} },
		"wrap 0x10001":     func(c *Config) { c.CountWrap = 65537 },
	} {
		c := Config{CB: testCB(), Src: src, Types: LE}
		mod(&c)
		if _, err := NewPublisher(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Covers: SIG-IPE-2099
func TestPublisherRunRealTime(t *testing.T) {
	p := newPub(t, func(c *Config) { c.CB.SmpMod, c.CB.SmpRate = SmpPerSecond, 1000 })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var got [][]byte
	stop := errors.New("enough")
	err := p.Run(ctx, time.Now(), leSource, synced, func(b []byte) error {
		got = append(got, b)
		if len(got) == 20 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || len(got) != 20 {
		t.Fatalf("Run: %v, %d frames", err, len(got))
	}
	as := decodeAll(t, got)
	for i := 1; i < len(as); i++ {
		if (int(as[i-1].SmpCnt)+1)%1000 != int(as[i].SmpCnt) {
			t.Errorf("smpCnt %d then %d", as[i-1].SmpCnt, as[i].SmpCnt)
		}
	}
	cancel()
	if err := p.Run(ctx, time.Now().Add(time.Hour), leSource, nil, func([]byte) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled Run: %v", err)
	}
}
