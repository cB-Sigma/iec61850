package tase2

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

func viaBER(t *testing.T, d mms.Data) mms.Data {
	t.Helper()
	e, _, err := mms.Parse(d.Encode())
	if err != nil {
		t.Fatal(err)
	}
	out, err := mms.DecodeData(e)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// IEC 60870-6-503 8.2.4 to 8.2.6: GMTBased S/M/H/D counts from 1970 GMT,
// TimeStampExtended {GMTBasedS, TimeIntervalL16 ms} and the interval
// types with their widths.
// Covers: SIG-IPE-1528
func TestTASE2TimeTypes(t *testing.T) {
	at := time.Date(2026, 9, 24, 13, 45, 30, 250e6, time.UTC)
	for _, c := range []struct {
		unit time.Duration
		want int64
	}{
		{UnitSecond, at.Unix()}, {UnitMinute, at.Unix() / 60}, {UnitHour, at.Unix() / 3600}, {UnitDay, at.Unix() / 86400},
	} {
		if got := GMTBased(at, c.unit); got != c.want {
			t.Errorf("GMTBased %v = %d, want %d", c.unit, got, c.want)
		}
	}
	// The first second, minute, hour and day of 1970 count 0.
	epoch := time.Unix(0, 0).UTC()
	for _, u := range []time.Duration{UnitSecond, UnitMinute, UnitHour, UnitDay} {
		if GMTBased(epoch.Add(u/2), u) != 0 || !FromGMTBased(1, u).Equal(epoch.Add(u)) {
			t.Errorf("unit %v: first unit is not 0", u)
		}
	}
	if GMTBasedS(time.Time{}) != 0 {
		t.Error("zero time is not 0")
	}
	ts := viaBER(t, TimeStampExtended(at))
	if len(ts.Elems) != 2 || ts.Elems[0].Int != at.Unix() || ts.Elems[1].Int != 250 {
		t.Errorf("TimeStampExtended = %+v", ts)
	}
	for _, c := range []struct {
		d    time.Duration
		unit time.Duration
		bits int
		ok   bool
		want int64
	}{
		{32767 * time.Millisecond, UnitMillisecond, 16, true, 32767}, // TimeIntervalL16
		{32768 * time.Millisecond, UnitMillisecond, 16, false, 0},
		{40 * 24 * time.Hour, UnitMillisecond, 32, false, 0}, // 3 456 000 000 ms exceeds TimeIntervalL32
		{20 * 24 * time.Hour, UnitMillisecond, 32, true, 1728000000},
		{90 * time.Minute, UnitMinute, 16, true, 90},     // TimeIntervalM
		{36 * time.Hour, UnitHour, 16, true, 36},         // TimeIntervalH
		{3 * UnitDay, UnitDay, 16, true, 3},              // TimeIntervalD
		{3600 * time.Second, UnitSecond, 32, true, 3600}, // TimeIntervalS
	} {
		d, err := Interval(c.d, c.unit, c.bits)
		if (err == nil) != c.ok || (c.ok && d.Int != c.want) {
			t.Errorf("Interval(%v, %v, %d) = %+v %v", c.d, c.unit, c.bits, d, err)
			continue
		}
		if c.ok {
			back, err := IntervalFrom(d, c.unit)
			if err != nil || back != c.d {
				t.Errorf("IntervalFrom = %v %v", back, err)
			}
		}
	}
}

// 8.2.9 and 8.2.10, 8.3.2 and 8.3.4: SupportedFeatures bit n-1 is block
// n (the blocks are named by IEC 60870-6-702:2014 Table A.2); TASE.2Version
// {Integer16, Integer16}, 2000.08 for this edition.
// Covers: SIG-IPE-1529
func TestTASE2FeaturesAndVersion(t *testing.T) {
	f := viaBER(t, mms.Bits(Features(1, 2, 4, 5)))
	if f.Bits.NBits != 12 || f.Bits.Bits[0] != 0b11011000 || f.Bits.Bits[1] != 0 {
		t.Errorf("features 1,2,4,5 = %08b %08b (%d bits)", f.Bits.Bits[0], f.Bits.Bits[1], f.Bits.NBits)
	}
	for n, want := range map[int]bool{1: true, 2: true, 3: false, 4: true, 5: true, 6: false, 12: false, 13: false, 0: false} {
		if Supports(f.Bits, n) != want {
			t.Errorf("Supports(%d) = %v", n, !want)
		}
	}
	if BlockName(4) != "information message" || BlockName(10) != "block 10 (not defined by IEC 60870-6-702:2014)" {
		t.Error("block names")
	}
	if Edition2014.String() != "2000.08" {
		t.Errorf("edition = %s", Edition2014)
	}
	v, err := VersionFrom(viaBER(t, Edition2014.Data()))
	if err != nil || v != Edition2014 {
		t.Errorf("version = %v %v", v, err)
	}
	for s, ok := range map[string]bool{"2000.08": true, "2000.8": true, "1996.08": true, "2000": false, "x.1": false, "2000.-1": false} {
		if _, err := ParseVersion(s); (err == nil) != ok {
			t.Errorf("ParseVersion(%q) = %v", s, err)
		}
	}
	if _, err := VersionFrom(mms.Structure(mms.Integer(70000), mms.Integer(1))); err == nil {
		t.Error("a 70000 major version was accepted")
	}
}

// 8.2.3: MMS ObjectName {Scope Unsigned8, DomainName, Name}; illegal
// identifiers are OBJECT-ATTRIBUTE-INCONSISTENT; a VMD name's domain is
// ignored. 8.2.7.1: the DSTransferSet component order and types.
// Covers: SIG-IPE-1530
func TestTASE2ObjectNameAndTransferSet(t *testing.T) {
	d := viaBER(t, ObjectNameData(mms.DomainName("ICC1", "DS_1")))
	if d.Elems[0].Kind != mms.KUint || d.Elems[0].Uint != 1 || d.Elems[1].Str != "ICC1" || d.Elems[2].Str != "DS_1" {
		t.Errorf("domain name = %+v", d)
	}
	v := viaBER(t, ObjectNameData(mms.VMDName("X")))
	if v.Elems[0].Uint != 0 || v.Elems[1].Str == "" {
		t.Errorf("VMD name = %+v", v)
	}
	if n, err := ObjectNameFrom(mms.Structure(mms.Unsigned(0), mms.Visible("anything"), mms.Visible("X"))); err != nil || n != mms.VMDName("X") {
		t.Errorf("VMD name read = %v %v", n, err)
	}
	for _, bad := range []mms.Data{
		mms.Structure(mms.Unsigned(1), mms.Visible("ICC 1"), mms.Visible("DS")),
		mms.Structure(mms.Unsigned(1), mms.Visible("ICC1"), mms.Visible("9DS")),
		mms.Structure(mms.Unsigned(1), mms.Visible("ICC1"), mms.Visible("DS-1")),
		mms.Structure(mms.Unsigned(0), mms.Visible("V"), mms.Visible("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456")),
	} {
		if _, err := ObjectNameFrom(bad); !errors.Is(err, ErrNameInconsistent) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if _, err := ObjectNameFrom(mms.Structure(mms.Unsigned(2), mms.Visible("A"), mms.Visible("B"))); err == nil {
		t.Error("scope 2 accepted")
	}
	ts := TransferSet{DataSet: mms.DomainName("ICC1", "DS_1"), Interval: 10 * time.Second, TLE: 30 * time.Second,
		IntegrityCheck: 5 * time.Minute, Conditions: Conditions(CondInterval, CondIntegrity, CondChange), BlockData: true,
		Critical: true, RBE: true, AllChangesReported: true, Status: true, EventCodeRequested: -5}
	d = viaBER(t, ts.Data())
	kinds := []mms.Kind{mms.KStructure, mms.KInt, mms.KInt, mms.KInt, mms.KInt, mms.KInt, mms.KBitString,
		mms.KBool, mms.KBool, mms.KBool, mms.KBool, mms.KBool, mms.KInt}
	for i, k := range kinds {
		if d.Elems[i].Kind != k {
			t.Errorf("component %d is %s, want %s", i+1, d.Elems[i].Kind, k)
		}
	}
	if d.Elems[6].Bits.Bits[0] != 0b11100000 || d.Elems[2].Int != 10 || d.Elems[5].Int != 300 || d.Elems[1].Int != 0 {
		t.Errorf("DSTransferSet = %+v", d)
	}
	got, err := TransferSetFrom(d)
	if err != nil || got.EventCodeRequested != -5 || !got.BlockData || !got.Critical || got.DataSet != ts.DataSet {
		t.Errorf("round trip = %+v %v", got, err)
	}
	bad := func(i int, v mms.Data) mms.Data {
		e := append([]mms.Data(nil), d.Elems...)
		e[i] = v
		return mms.Structure(e...)
	}
	for i, b := range []mms.Data{
		bad(2, mms.Integer(-1)), bad(1, mms.Visible("now")), bad(6, mms.Integer(1)), bad(8, mms.Integer(1)),
		bad(12, mms.Integer(40000)), bad(0, mms.Structure(mms.Unsigned(1), mms.Visible("ICC1"), mms.Visible("bad name"))),
		mms.Structure(d.Elems[:12]...),
	} {
		if _, err := TransferSetFrom(b); err == nil {
			t.Errorf("bad transfer set %d accepted", i)
		}
	}
	// DSConditions bit positions (8.2.8.1).
	for bit, name := range []string{"interval", "integrity", "change", "operator", "external"} {
		if n := ConditionNames(Conditions(bit)); len(n) != 1 || n[0] != name {
			t.Errorf("bit %d = %v", bit, n)
		}
	}
	if !IsSpecial(VarEventCode) || IsSpecial("LINE1_MW") {
		t.Error("IsSpecial")
	}
}

// 7.2.5.5.2: the acknowledgement report carries Transfer_Report_ACK (the
// transfer set name) and Transfer_Set_Time_Stamp (echoed) in the transfer
// set's domain; the negative one Transfer_Report_NACK.
// Covers: SIG-IPE-1531
func TestTASE2ReportAcknowledgement(t *testing.T) {
	ts := mms.DomainName("ICC_SLDC", "DSTrans3")
	spec, res := AckReport(ts, mms.Integer(1_790_000_000))
	if len(spec.Vars) != 2 || spec.Vars[0] != mms.DomainName("ICC_SLDC", "Transfer_Report_ACK") ||
		spec.Vars[1] != mms.DomainName("ICC_SLDC", "Transfer_Set_Time_Stamp") {
		t.Fatalf("ack spec = %+v", spec)
	}
	// Through the wire as the server receives it.
	e, _, err := mms.Parse(mms.InformationReportPDU(spec, res))
	if err != nil {
		t.Fatal(err)
	}
	r, err := mms.DecodeInformationReport(e)
	if err != nil {
		t.Fatal(err)
	}
	a, ok, err := AckFrom(r)
	if !ok || err != nil || a.Negative || a.TransferSet != ts || a.Stamp != 1_790_000_000 {
		t.Errorf("ack = %+v %v %v", a, ok, err)
	}
	spec, res = NackReport(ts)
	a, ok, err = AckFrom(mms.InformationReport{Spec: spec, Results: res})
	if !ok || err != nil || !a.Negative || a.TransferSet != ts || spec.Vars[0].Domain != "ICC_SLDC" {
		t.Errorf("nack = %+v %v %v", a, ok, err)
	}
	if _, ok, _ := AckFrom(mms.InformationReport{Spec: mms.VariableSpec{Vars: []mms.ObjectName{mms.VMDName("X")}},
		Results: []mms.AccessResult{{Data: mms.Integer(1)}}}); ok {
		t.Error("another report read as an acknowledgement")
	}
	if _, ok, err := AckFrom(mms.InformationReport{Spec: mms.VariableSpec{Vars: []mms.ObjectName{mms.DomainName("I", VarReportACK)}},
		Results: []mms.AccessResult{{Data: ObjectNameData(ts)}}}); !ok || err == nil {
		t.Error("an acknowledgement without its time stamp was accepted")
	}
}

// 7.2.5.5.3 Block Data: rule octet, then values in storage form; rule 0
// every member in order, rules 1 and 2 a 1- or 2-octet position before
// each value.
// Covers: SIG-IPE-1532
func TestTASE2BlockedReports(t *testing.T) {
	members := []BlockMember{{3, "realQ"}, {4, "stateQTimeTag"}, {5, "discreteQTimeTagExtended"}}
	vals := []mms.Data{
		mms.Structure(mms.Float32(1.5), bitsOf(0b00100000, 8)),
		mms.Structure(mms.Integer(1_000_000_000), bitsOf(0b10000000, 8)),
		mms.Structure(mms.Integer(-7), mms.Structure(mms.Integer(1_000_000_001), mms.Integer(999)), bitsOf(0, 8)),
	}
	ptr := func(d mms.Data) *mms.Data { return &d }
	all, err := EncodeBlock(RuleAll, members, []*mms.Data{ptr(vals[0]), ptr(vals[1]), ptr(vals[2])})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0x3f, 0xc0, 0, 0, 0x20, 0x3b, 0x9a, 0xca, 0x00, 0x80,
		0xff, 0xff, 0xff, 0xf9, 0x3b, 0x9a, 0xca, 0x01, 0x03, 0xe7, 0x00}
	if string(all) != string(want) {
		t.Errorf("rule 0 = % x\nwant     % x", all, want)
	}
	got, err := DecodeBlock(all, members)
	if err != nil || len(got) != 3 || got[3].Elems[0].Float != 1.5 || got[4].Elems[0].Int != 1_000_000_000 ||
		got[5].Elems[0].Int != -7 || got[5].Elems[1].Elems[1].Int != 999 {
		t.Errorf("rule 0 decoded = %+v %v", got, err)
	}
	v, err := Decode("stateQTimeTag", got[4])
	if err != nil || v.State != StateClosed {
		t.Errorf("decoded state = %+v %v", v, err)
	}
	one, _ := EncodeBlock(RuleOffset1, members, []*mms.Data{nil, ptr(vals[1]), nil})
	if string(one) != string([]byte{1, 4, 0x3b, 0x9a, 0xca, 0x00, 0x80}) {
		t.Errorf("rule 1 = % x", one)
	}
	two, _ := EncodeBlock(RuleOffset2, members, []*mms.Data{ptr(vals[0]), nil, nil})
	if string(two) != string([]byte{2, 0, 3, 0x3f, 0xc0, 0, 0, 0x20}) {
		t.Errorf("rule 2 = % x", two)
	}
	for _, b := range [][]byte{one, two} {
		got, err := DecodeBlock(b, members)
		if err != nil || len(got) != 1 {
			t.Errorf("% x decoded = %v %v", b, got, err)
		}
	}
	for _, b := range [][]byte{{}, {3}, {1, 9, 0}, {0, 0x3f}, append(append([]byte{}, all...), 0), {2, 0}} {
		if _, err := DecodeBlock(b, members); err == nil {
			t.Errorf("% x decoded", b)
		}
	}
	if _, err := EncodeBlock(RuleAll, members, []*mms.Data{nil, nil, nil}); err == nil {
		t.Error("rule 0 with a missing member")
	}
}

// 802 6.3, 7.2: device outage report variables by activity, with the code
// tables (the duplicate forced code of F-506 reads as forced).
// Covers: SIG-IPE-1533
func TestTASE2DeviceOutage(t *testing.T) {
	common := []mms.Data{mms.Integer(4711), mms.Integer(12), mms.Integer(1_790_000_000), mms.Visible("Bawana"),
		mms.Visible("GT-3"), mms.Integer(1), mms.Integer(3), mms.Float32(216), mms.Integer(1_790_003_600)}
	actual := mms.Structure(append(append([]mms.Data{}, common...), mms.Integer(0), mms.Float32(180), mms.Visible("trip"), mms.Visible("none"))...)
	o, err := OutageFrom(VarOutageActual, viaBER(t, actual))
	if err != nil {
		t.Fatal(err)
	}
	if o["activity"] != "actual" || o["deviceType"] != "generator" || o["action"] != "tripped" || o["stationName"] != "Bawana" ||
		o["timeStamp"] != "2026-09-21T14:13:20Z" || o["outageReferenceId"] != int64(4711) || o["affectedAmount"] != 180.0 {
		t.Errorf("DO_Actual = %v", o)
	}
	sched := mms.Structure(append(append([]mms.Data{}, common...), mms.Integer(1), mms.Integer(1_790_010_000), mms.Integer(0),
		mms.Integer(2), mms.Integer(5), mms.Integer(1), mms.Float32(50), mms.Float32(200), mms.Float32(20), mms.Integer(0),
		mms.Visible("c"), mms.Visible("e"))...)
	o, err = OutageFrom(VarOutageRevise, sched)
	if err != nil || o["activity"] != "revise" || o["planType"] != "estimated" || o["outagePeriod"] != "daily" ||
		o["outageType"] != "forced" || o["class"] != "out-of-service" || o["plannedCloseOrInService"] != nil {
		t.Errorf("DO_Rev_Sched = %v %v", o, err)
	}
	if _, err := OutageFrom(VarOutageCancel, actual); err == nil {
		t.Error("a DOActual read as DOCancel")
	}
	if !IsOutage(VarOutageNew) || IsOutage("DO_Other") {
		t.Error("IsOutage")
	}
}

// 6.8, 8.5: information buffer variable names and sizes.
// Covers: SIG-IPE-1534
func TestTASE2InformationBufferNames(t *testing.T) {
	for n, want := range map[int]int{0: 64, 64: 64, 65: 256, 1024: 1024, 1025: 2048} {
		if InfoBufferSize(n) != want {
			t.Errorf("InfoBufferSize(%d) = %d", n, InfoBufferSize(n))
		}
	}
	for s, ok := range map[string]bool{"Info_Buff_256": true, "Info_Buf_64": true, "Info_Buff_x": false, "Info_Mess_Header": false} {
		if IsInfoBuffer(s) != ok {
			t.Errorf("IsInfoBuffer(%q)", s)
		}
	}
}

// Device outage reports encode from named fields and decode back (IEC
// 60870-6-802 6.3, 7.2), for the server role.
// Covers: SIG-IPE-1549
func TestTASE2DeviceOutageEncode(t *testing.T) {
	in := map[string]any{"outageReferenceId": 4711.0, "owningUtilityId": 12.0, "timeStamp": "2026-09-21T14:13:20Z",
		"stationName": "Bawana", "deviceName": "GT-3", "deviceType": "generator", "deviceNumber": 3.0, "deviceRating": 216.0,
		"activityDateAndTime": "2026-09-21T15:13:20Z", "action": "tripped", "affectedAmount": 180.0, "comments": "trip", "outageEffect": "none"}
	for act, item := range map[string]string{"new-plan": VarOutageNew, "revise": VarOutageRevise, "cancel": VarOutageCancel, "actual": VarOutageActual} {
		got, err := OutageItem(act)
		if err != nil || got != item {
			t.Errorf("OutageItem(%s) = %s %v", act, got, err)
		}
	}
	if _, err := OutageItem("maybe"); err == nil {
		t.Error("unknown activity")
	}
	d, err := OutageData(VarOutageActual, in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := OutageFrom(VarOutageActual, viaBER(t, d))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range in {
		want := v
		if f, ok := v.(float64); ok && k != "deviceRating" && k != "affectedAmount" {
			want = int64(f)
		}
		if out[k] != want {
			t.Errorf("%s = %v (%T), want %v", k, out[k], out[k], want)
		}
	}
	sched, err := OutageData(VarOutageNew, map[string]any{"planType": "estimated", "outagePeriod": 2.0, "outageType": "economy", "class": "in-service"})
	if err != nil || len(sched.Elems) != 21 || sched.Elems[9].Int != 1 || sched.Elems[12].Int != 2 || sched.Elems[13].Int != 3 || sched.Elems[18].Int != 1 {
		t.Errorf("DONewRevSched = %+v %v", sched, err)
	}
	for _, bad := range []map[string]any{
		{"deviceType": "reactor"}, {"timeStamp": "yesterday"}, {"stationName": strings.Repeat("x", 33)},
		{"deviceRating": "big"}, {"deviceNumber": 1e12},
	} {
		if _, err := OutageData(VarOutageActual, bad); err == nil {
			t.Errorf("%v was encoded", bad)
		}
	}
}
