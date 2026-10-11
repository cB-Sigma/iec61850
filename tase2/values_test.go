package tase2

import (
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

// Covers: SIG-IPE-350
func TestICCPPointTypesRoundTrip(t *testing.T) {
	at := time.Date(2026, 9, 1, 10, 0, 5, 0, time.UTC)
	for typ := range types {
		v := Value{Real: 12.5, Discrete: 12, State: StateClosed, Time: at.Add(250 * time.Millisecond), COV: 7,
			Flags: Flags{Validity: Suspect, Source: Estimated, Abnormal: true}}
		d, err := Encode(typ, v)
		if err != nil {
			t.Fatal(err)
		}
		// Through the BER encoding, as it travels.
		e, _, err := mms.Parse(d.Encode())
		if err != nil {
			t.Fatal(err)
		}
		d2, err := mms.DecodeData(e)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(typ, d2)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		l := types[typ]
		switch l.base {
		case "real":
			if got.Real != 12.5 {
				t.Errorf("%s value = %v", typ, got.Real)
			}
		case "discrete":
			if got.Discrete != 12 {
				t.Errorf("%s value = %v", typ, got.Discrete)
			}
		case "state":
			if got.State != StateClosed || got.JSON(typ) != StateClosed {
				t.Errorf("%s state = %v", typ, got.State)
			}
		}
		hasFlags := false
		hasTime, hasExt, hasCOV := false, false, false
		for _, f := range l.fields {
			switch f {
			case fFlags, fState:
				hasFlags = true
			case fTime:
				hasTime = true
			case fTimeExt:
				hasExt = true
			case fCOV:
				hasCOV = true
			}
		}
		if hasFlags && got.Flags.Quality() != "suspect,estimated,abnormal" {
			t.Errorf("%s quality = %q", typ, got.Flags.Quality())
		}
		if hasTime && !got.Time.Equal(at) {
			t.Errorf("%s time = %v", typ, got.Time)
		}
		if hasExt && !got.Time.Equal(at.Add(250*time.Millisecond)) {
			t.Errorf("%s extended time = %v", typ, got.Time)
		}
		if hasCOV && got.COV != 7 {
			t.Errorf("%s COV = %d", typ, got.COV)
		}
	}
	// Bit layout of the flags: state in bits 0-1, validity 2-3, source
	// 4-5, normal value 6, time stamp quality 7 (IEC 60870-6-802).
	d, _ := Encode("state", Value{State: StateTripped, Flags: Flags{Validity: NotValid, TimeInvalid: true}})
	if got := d.Bits.Bits[0]; got != 0b01110001 {
		t.Errorf("state bits = %08b", got)
	}
	if q := (Flags{}).Quality(); q != "good" {
		t.Errorf("nominal flags quality = %q", q)
	}
	// Wrong shapes are refused.
	if _, err := Decode("realQ", mms.Float32(1)); err == nil {
		t.Error("a bare float decoded as realQ")
	}
	if _, err := Decode("real", mms.Visible("x")); err == nil {
		t.Error("a string decoded as real")
	}
	if Type("nonsense").Valid() {
		t.Error("an unknown type is valid")
	}
}

// Covers: SIG-IPE-353
func TestICCPTransferSetAndConditions(t *testing.T) {
	ts := TransferSet{DataSet: mms.DomainName("ICC1", "DS1"), StartTime: time.Unix(1_700_000_000, 0).UTC(),
		Interval: 10 * time.Second, TLE: 30 * time.Second, BufferTime: 2 * time.Second, IntegrityCheck: time.Minute,
		Conditions: Conditions(CondChange, CondIntegrity), RBE: true, AllChangesReported: true, Status: true, EventCodeRequested: 3}
	e, _, err := mms.Parse(ts.Data().Encode())
	if err != nil {
		t.Fatal(err)
	}
	d, _ := mms.DecodeData(e)
	got, err := TransferSetFrom(d)
	if err != nil {
		t.Fatal(err)
	}
	if got.DataSet != ts.DataSet || !got.StartTime.Equal(ts.StartTime) || got.Interval != ts.Interval || got.TLE != ts.TLE ||
		got.BufferTime != ts.BufferTime || got.IntegrityCheck != ts.IntegrityCheck || !got.RBE || !got.Status ||
		!got.AllChangesReported || got.EventCodeRequested != 3 {
		t.Errorf("transfer set round trip = %+v", got)
	}
	if n := ConditionNames(got.Conditions); len(n) != 2 || n[0] != "integrity" || n[1] != "change" {
		t.Errorf("conditions = %v", n)
	}
	if b := Blocks(Features(1, 2, 5)); len(b) != 3 || b[2] != 5 {
		t.Errorf("blocks = %v", b)
	}
	if _, err := TransferSetFrom(mms.Integer(1)); err == nil {
		t.Error("an integer decoded as a transfer set")
	}
	n, err := ObjectNameFrom(ObjectNameData(mms.VMDName("X")))
	if err != nil || n != mms.VMDName("X") {
		t.Errorf("VMD object name = %v %v", n, err)
	}
}

func bitsOf(b byte, n int) mms.Data {
	return mms.Bits(mms.BitString{Bits: []byte{b}, NBits: n})
}

// Clause 6.2.1 (Data_State, Data_Flags bit numbering) and 7.1.1 (codes of
// validity, current source, normal value and time stamp quality); the
// state codes of the table in 8.2.
// Covers: SIG-IPE-1520
func TestICCP802FlagLayout(t *testing.T) {
	for _, c := range []struct {
		bits byte
		want Flags
		q    string
	}{
		{0b00000000, Flags{}, "good"},
		{0b00010000, Flags{Validity: Held}, "held"},
		{0b00100000, Flags{Validity: Suspect}, "suspect"},
		{0b00110000, Flags{Validity: NotValid}, "invalid"},
		{0b00000100, Flags{Source: Calculated}, "calculated"},
		{0b00001000, Flags{Source: Entered}, "entered"},
		{0b00001100, Flags{Source: Estimated}, "estimated"},
		{0b00000010, Flags{Abnormal: true}, "abnormal"},
		{0b00000001, Flags{TimeInvalid: true}, "time-invalid"},
		{0b11000000, Flags{}, "good"}, // bits 0-1 of Data_Flags are unused
	} {
		v, err := Decode("realQ", mms.Structure(mms.Float32(1), bitsOf(c.bits, 8)))
		if err != nil || v.Flags != c.want || v.Quality() != c.q {
			t.Errorf("flags %08b = %+v %q %v", c.bits, v.Flags, v.Quality(), err)
		}
		d, _ := Encode("realQ", Value{Real: 1, Flags: c.want})
		if want := c.bits &^ 0b11000000; d.Elems[1].Bits.Bits[0] != want {
			t.Errorf("encoded flags %+v = %08b, want %08b", c.want, d.Elems[1].Bits.Bits[0], want)
		}
	}
	// Data_State: the state in bits 0-1 (00 between, 01 tripped/off, 10
	// closed/on, 11 invalid for a disconnector).
	for bits, st := range map[byte]int{0x00: StateBetween, 0x40: StateTripped, 0x80: StateClosed, 0xc0: StateInvalid} {
		v, err := Decode("state", bitsOf(bits, 8))
		if err != nil || v.State != st || v.JSON("state") != st {
			t.Errorf("Data_State %08b = %d %v", bits, v.State, err)
		}
	}
	// Data_StateQ is {Value Data_State, Flags Data_Flags} in the 2014
	// edition; the flags come from the Flags component.
	d, _ := Encode("stateQ", Value{State: StateClosed, Flags: Flags{Validity: Suspect}})
	if d.Kind != mms.KStructure || len(d.Elems) != 2 || d.Elems[0].Bits.Bits[0] != 0b10100000 || d.Elems[1].Bits.Bits[0] != 0b00100000 {
		t.Errorf("Data_StateQ = %+v", d)
	}
	v, err := Decode("stateQ", mms.Structure(bitsOf(0b01000000, 8), bitsOf(0b00001000, 8)))
	if err != nil || v.State != StateTripped || v.Quality() != "entered" {
		t.Errorf("Data_StateQ decoded = %+v %v", v, err)
	}
	// The earlier single bit string form is still read (findings F-500).
	v, err = Decode("stateQ", bitsOf(0b10110000, 8))
	if err != nil || v.State != StateClosed || v.Quality() != "invalid" {
		t.Errorf("legacy Data_StateQ = %+v %v", v, err)
	}
	// Component order of the time-tagged state types: time stamp first,
	// then the Data_State.
	d, _ = Encode("stateQTimeTag", Value{State: StateClosed, Time: time.Unix(1_000_000_000, 0)})
	if d.Elems[0].Kind != mms.KInt || d.Elems[0].Int != 1_000_000_000 || d.Elems[1].Kind != mms.KBitString {
		t.Errorf("Data_StateQTimeTag = %+v", d)
	}
	// COV_Counter is unsigned 16 bits; Data_RealExtended is value, time,
	// flags, counter.
	d, _ = Encode("realExtended", Value{Real: 2, COV: 65537})
	if len(d.Elems) != 4 || d.Elems[3].Kind != mms.KUint || d.Elems[3].Uint != 1 {
		t.Errorf("Data_RealExtended = %+v", d)
	}
}

// Clause 6.2.1 Data_StateSupplemental and its Q, QTimeTag, Extended and
// QTimeTagExtended forms.
// Covers: SIG-IPE-1521
func TestICCP802StateSupplemental(t *testing.T) {
	// state 10 (closed), tag 01 (open and close inhibit), expected 01.
	b := bitsOf(0b10010100, 8)
	v, err := Decode("stateSupplemental", b)
	if err != nil || v.State != StateClosed || v.Tag != TagOpenCloseInhibit || v.ExpectedState != StateTripped {
		t.Fatalf("Data_StateSupplemental = %+v %v", v, err)
	}
	if m := v.JSON("stateSupplemental").(map[string]any); m["tag"] != "open-and-close-inhibit" || m["expectedState"] != 1 || m["state"] != 2 {
		t.Errorf("JSON = %v", m)
	}
	for typ, n := range map[Type]int{"stateSupplementalQ": 2, "stateSupplementalQTimeTag": 3,
		"stateSupplementalExtended": 4, "stateSupplementalQTimeTagExtended": 3} {
		in := Value{State: StateTripped, Tag: TagCloseInhibit, ExpectedState: StateClosed, Flags: Flags{Validity: Held}, COV: 3,
			Time: time.Unix(1_700_000_000, 0).UTC()}
		d, err := Encode(typ, in)
		if err != nil || len(d.Elems) != n || d.Elems[0].Bits.Bits[0] != 0b01101000 {
			t.Errorf("%s = %+v %v", typ, d, err)
			continue
		}
		got, err := Decode(typ, d)
		if err != nil || got.State != in.State || got.Tag != in.Tag || got.ExpectedState != in.ExpectedState || got.Quality() != "held" {
			t.Errorf("%s round trip = %+v %v", typ, got, err)
		}
	}
}

// Clause 7.1.1: the point type selection table and the
// IndicationPointConfig codes.
// Covers: SIG-IPE-1522
func TestICCP802PointTypeSelection(t *testing.T) {
	bases := []string{"state", "discrete", "real", "stateSupplemental"}
	for pt, base := range bases {
		for _, c := range []struct {
			q, ts, cov int
			want       string
		}{
			{0, 0, 0, base}, {1, 0, 0, base + "Q"}, {1, 1, 0, base + "QTimeTag"},
			{1, 2, 0, base + "QTimeTagExtended"}, {1, 1, 1, base + "Extended"}, {0, 0, 1, base + "Extended"},
		} {
			pc, err := PointConfigFrom(PointConfig{PointType: pt, QualityClass: c.q, TimeStampClass: c.ts, COVClass: c.cov}.Data())
			if err != nil {
				t.Fatal(err)
			}
			got, err := pc.Type()
			if err != nil || string(got) != c.want || !got.Valid() {
				t.Errorf("config %+v = %q %v, want %s", pc, got, err, c.want)
			}
		}
	}
	if _, err := (PointConfig{PointType: 2, TimeStampClass: 1}).Type(); err == nil {
		t.Error("a time stamp without quality selected a type")
	}
	for _, bad := range []mms.Data{
		PointConfig{PointType: 4}.Data(), PointConfig{TimeStampClass: 3}.Data(), PointConfig{NormalSource: 4}.Data(),
		mms.Structure(mms.Integer(0)), mms.Structure(mms.Integer(0), mms.Integer(0), mms.Integer(0), mms.Integer(0), mms.Float32(0)),
	} {
		if _, err := PointConfigFrom(bad); err == nil {
			t.Errorf("IndicationPointConfig %+v was accepted", bad)
		}
	}
}

// Clauses 6.2.2, 7.1.2 and 8.3: ControlConfig selection, TagFlags and
// Tag_Value, the SBO structure, SBO_CheckBackName and command values.
// Covers: SIG-IPE-1523
func TestICCP802ControlPoint(t *testing.T) {
	for _, c := range []struct {
		cfg  ControlConfig
		want string
	}{
		{ControlConfig{ControlPointType: 0}, "command"},
		{ControlConfig{ControlPointType: 1, SetPointType: 2}, "real"},
		{ControlConfig{ControlPointType: 1, SetPointType: 1, DeviceClass: 1, TagClass: 1}, "discrete"},
		{ControlConfig{ControlPointType: 1, SetPointType: 0}, ""},
		{ControlConfig{ControlPointType: 2}, ""},
	} {
		got, err := ControlConfigFrom(c.cfg.Data())
		if err != nil || got != c.cfg {
			t.Fatalf("ControlConfig round trip %+v = %+v %v", c.cfg, got, err)
		}
		k, err := got.Kind()
		if k != c.want || (c.want == "") != (err != nil) {
			t.Errorf("ControlConfig %+v kind = %q %v", c.cfg, k, err)
		}
	}
	// TagFlags: tag in bits 0-1, state (armed) in bit 2.
	for _, c := range []struct {
		bits byte
		tag  TagValue
	}{
		{0b00000000, TagValue{Tag: TagNone}},
		{0b01000000, TagValue{Tag: TagOpenCloseInhibit}},
		{0b10100000, TagValue{Tag: TagCloseInhibit, Armed: true}},
	} {
		c.tag.Reason = "line work"
		d := c.tag.Data()
		if d.Elems[0].Bits.NBits != 3 || d.Elems[0].Bits.Bits[0] != c.bits || d.Elems[1].Str != "line work" {
			t.Errorf("Tag_Value %+v = %+v", c.tag, d)
		}
		got, err := TagValueFrom(d)
		if err != nil || got != c.tag {
			t.Errorf("Tag_Value round trip = %+v %v", got, err)
		}
	}
	open, closeCmd := int64(CommandOff), int64(CommandOn)
	for _, c := range []struct {
		tag     int
		command bool
		value   int64
		inhibit bool
	}{
		{TagNone, true, closeCmd, false}, {TagOpenCloseInhibit, true, open, true}, {TagOpenCloseInhibit, false, 5, true},
		{TagCloseInhibit, true, closeCmd, true}, {TagCloseInhibit, true, open, false}, {TagCloseInhibit, false, 1, false},
		{3, true, open, true},
	} {
		if got := (TagValue{Tag: c.tag}).Inhibits(c.command, c.value); got != c.inhibit {
			t.Errorf("tag %d inhibits command=%v value %d = %v", c.tag, c.command, c.value, got)
		}
	}
	if TagName(3) != "invalid" || TagName(TagCloseInhibit) != "close-only-inhibit" {
		t.Error("tag names")
	}
	if _, err := TagValueFrom(mms.Structure(bitsOf(0, 3), mms.Integer(1))); err == nil {
		t.Error("a Tag_Value with a numeric reason was accepted")
	}
	// SBO: {TimeOut GMTBasedS, Select boolean}.
	sbo := SBOState{TimeOut: time.Unix(1_700_000_030, 0).UTC(), Selected: true}
	got, err := SBOStateFrom(sbo.Data())
	if err != nil || got != sbo {
		t.Errorf("SBO round trip = %+v %v", got, err)
	}
	if _, err := SBOStateFrom(mms.Structure(mms.Integer(0), mms.Integer(1))); err == nil {
		t.Error("an SBO with an integer select state was accepted")
	}
	// SBO_CheckBackName is a 16-bit integer.
	if cb, err := CheckBackFrom(mms.Integer(1201)); err != nil || cb != 1201 {
		t.Errorf("check-back = %d %v", cb, err)
	}
	for _, bad := range []mms.Data{mms.Integer(70000), mms.Visible("BRK1"), mms.Float32(1)} {
		if _, err := CheckBackFrom(bad); err == nil {
			t.Errorf("check-back %+v was accepted", bad)
		}
	}
}

// Clauses 6.2.3 and 7.1.3: SingleFlags, EventFlags and PackedFlags and the
// protection event structures.
// Covers: SIG-IPE-1526
func TestICCP802ProtectionEvents(t *testing.T) {
	at := time.Date(2026, 9, 1, 10, 0, 0, 125e6, time.UTC)
	// SingleFlags: elapsed time invalid (0), blocked (1), substituted (2),
	// not topical (3), event invalid (4), event state (6-7: 01 off, 10 on).
	d := mms.Structure(bitsOf(0b01000010, 8), mms.Integer(40),
		mms.Structure(mms.Integer(at.Unix()), mms.Integer(125)))
	v, err := Decode("singleProtectionEvent", d)
	if err != nil {
		t.Fatal(err)
	}
	if m := v.JSON("singleProtectionEvent").(map[string]any); m["state"] != "on" || m["durationMs"] != int64(40) ||
		v.Quality() != "blocked" || !v.Time.Equal(at) {
		t.Errorf("single event = %v %q %v", m, v.Quality(), v.Time)
	}
	for bits, st := range map[byte]string{0x00: "invalid", 0x01: "off", 0x02: "on", 0x03: "invalid"} {
		v, _ := Decode("singleProtectionEvent", mms.Structure(bitsOf(bits, 8), mms.Integer(0), mms.Structure(mms.Integer(0), mms.Integer(0))))
		if v.JSON("singleProtectionEvent").(map[string]any)["state"] != st {
			t.Errorf("event state %02b", bits)
		}
	}
	// EventFlags: general (0), phases 1-3 (1-3), earth (4), reverse (5);
	// PackedFlags as SingleFlags without the state.
	d = mms.Structure(bitsOf(0b10101000, 8), bitsOf(0b00111000, 8), mms.Integer(65),
		mms.Structure(mms.Integer(at.Unix()), mms.Integer(125)))
	v, err = Decode("packedProtectionEvent", d)
	if err != nil {
		t.Fatal(err)
	}
	m := v.JSON("packedProtectionEvent").(map[string]any)
	if m["general"] != true || m["phase1"] != false || m["phase2"] != true || m["earth"] != true || m["reverse"] != false ||
		m["operatingTimeMs"] != int64(65) || v.Quality() != "substituted,not-topical,invalid" {
		t.Errorf("packed event = %v %q", m, v.Quality())
	}
	e, _ := Encode("packedProtectionEvent", v)
	if e.Elems[0].Bits.Bits[0] != 0b10101000 || e.Elems[1].Bits.Bits[0] != 0b00111000 || e.Elems[2].Int != 65 {
		t.Errorf("packed event encoded = %+v", e)
	}
}

// Clauses 6.4 and 7.3: InfoMessHeader and InfoBufXX.
// Covers: SIG-IPE-1527
func TestICCP802InformationBuffer(t *testing.T) {
	for n, want := range map[int]string{64: "InfoBuf64", 256: "InfoBuf256", 1024: "InfoBuf1024"} {
		if InfoBufName(n) != want {
			t.Errorf("InfoBufName(%d) = %s", n, InfoBufName(n))
		}
	}
	m := InfoMessage{InfoReference: 7, LocalReference: 42, MessageID: 1001, Data: []byte("Outage of line 3 at 14:00")}
	h, b := m.HeaderData(), m.BufferData(64)
	if len(h.Elems) != 4 || h.Elems[3].Int != int64(len(m.Data)) || len(b.Bytes) != 64 {
		t.Fatalf("header %+v, buffer %d octets", h, len(b.Bytes))
	}
	got, err := InfoMessageFrom(h, b)
	if err != nil || string(got.Data) != string(m.Data) || got.MessageID != 1001 || got.LocalReference != 42 {
		t.Errorf("message = %+v %v", got, err)
	}
	if _, err := InfoMessageFrom(mms.Structure(mms.Integer(1), mms.Integer(0), mms.Integer(1), mms.Integer(65)), b); err == nil {
		t.Error("a size beyond the buffer was accepted")
	}
	if _, err := InfoMessageFrom(h, mms.Visible("text")); err == nil {
		t.Error("a visible string buffer was accepted")
	}
	if !IsInfoHeader(h) || IsInfoHeader(mms.Structure(mms.Integer(1))) {
		t.Error("IsInfoHeader")
	}
}
