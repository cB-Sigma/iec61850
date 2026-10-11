package iec61850

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

// Covers: SIG-IPE-1800
func TestObjectNameMapping(t *testing.T) {
	// 8-1 7.3.1 Figure 4: the functional constraints of the MMS type
	// description; XX (service wildcard) is not mapped.
	for _, fc := range strings.Fields("MX ST CO CF DC SP SG RP LG BR GO GS SV SE MS US EX SR OR BL RG RS") {
		if _, err := ParseRef("LD1/XCBR1$"+fc+"$Pos", ""); err != nil {
			t.Errorf("FC %s refused: %v", fc, err)
		}
	}
	for _, fc := range []string{"XX", "SC", "NS", "st"} {
		if _, err := ParseRef("LD1/XCBR1$"+fc+"$Pos", ""); err == nil {
			t.Errorf("FC %s accepted", fc)
		}
	}
	// 8-1 7.3.3 and 7.3.4 examples: LN$FC$DO[$SDO][$DA[$BDA]].
	for _, c := range []struct{ dotted, fc, item string }{
		{"LD1/XCBR1.Pos", "ST", "XCBR1$ST$Pos"},
		{"LD1/MMXU1.A.phsA", "MX", "MMXU1$MX$A$phsA"},
		{"LD1/XCBR1.Pos.stVal", "ST", "XCBR1$ST$Pos$stVal"},
		{"LD1/XCBR1.Pos.origin.orCat", "ST", "XCBR1$ST$Pos$origin$orCat"},
	} {
		r, err := ParseRef(c.dotted, c.fc)
		if err != nil || r.MMS() != mms.DomainName("LD1", c.item) {
			t.Errorf("%s [%s] = %v, %v; want %s", c.dotted, c.fc, r.MMS(), err, c.item)
		}
		if back := RefFromMMS(r.MMS()); back.String() != c.dotted || back.FC != c.fc {
			t.Errorf("%s back = %s [%s]", c.item, back.String(), back.FC)
		}
	}
	// MMS identifiers are at most 64 characters (8-1 8.1.3.2.2, F.3.2).
	long := "LD1/GGIO1." + strings.Repeat("x", 60)
	if _, err := ParseRef(long, "ST"); err == nil {
		t.Error("an item over 64 characters was accepted")
	}
	if _, err := ParseRef(strings.Repeat("L", 65)+"/GGIO1.Ind", "ST"); err == nil {
		t.Error("a domain over 64 characters was accepted")
	}
	// ObjectReference of control block attributes (8-1 8.1.3.2.2):
	// domain, association and VMD scope, at most 129 characters.
	for _, c := range []struct {
		ref   string
		scope mms.Scope
		dom   string
		item  string
	}{
		{"LD1/LLN0$DS1", mms.ScopeDomain, "LD1", "LLN0$DS1"},
		{"LD1/LLN0.DS1", mms.ScopeDomain, "LD1", "LLN0$DS1"},
		{"@DS1", mms.ScopeAA, "", "DS1"},
		{"/DS1", mms.ScopeVMD, "", "DS1"},
	} {
		n, err := ParseObjectReference(c.ref)
		if err != nil || n.Scope != c.scope || n.Domain != c.dom || n.Item != c.item {
			t.Errorf("%s = %+v, %v", c.ref, n, err)
		}
		if want := strings.Replace(c.ref, ".", "$", 1); FormatObjectReference(n) != want {
			t.Errorf("%s formats as %s", c.ref, FormatObjectReference(n))
		}
	}
	for _, bad := range []string{"", "DS1", "@", "LD1/", "LD1/" + strings.Repeat("x", 126), "@a b"} {
		if _, err := ParseObjectReference(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Covers: SIG-IPE-1801
func TestQualityMapping(t *testing.T) {
	// 8-1 8.2 Table 44: validity invalid is 0x40 in the first octet.
	inv := mms.BitString{Bits: []byte{0x40, 0x00}, NBits: 13}
	if q := QualityJSON(inv); q["validity"] != "invalid" || q["source"] != "process" || q["test"] != false {
		t.Errorf("0x40 = %v", q)
	}
	for bits, want := range map[[2]byte]string{{0x00, 0}: "good", {0x40, 0}: "invalid", {0x80, 0}: "reserved", {0xc0, 0}: "questionable"} {
		if q := QualityJSON(mms.BitString{Bits: bits[:], NBits: 13}); q["validity"] != want {
			t.Errorf("%x = %v, want %s", bits, q["validity"], want)
		}
	}
	// Bits 2-9 are the detail flags in Table 44 order, 10 source, 11 test,
	// 12 operatorBlocked.
	details := []string{"overflow", "outOfRange", "badReference", "oscillatory", "failure", "oldData", "inconsistent", "inaccurate"}
	for i, name := range details {
		b := mms.NewBitString(13)
		b.Set(2+i, true)
		d, _ := QualityJSON(b)["details"].([]any)
		if len(d) != 1 || d[0] != name {
			t.Errorf("bit %d = %v, want %s", 2+i, d, name)
		}
	}
	b := mms.NewBitString(13)
	b.Set(10, true)
	b.Set(11, true)
	b.Set(12, true)
	if q := QualityJSON(b); q["source"] != "substituted" || q["test"] != true || q["operatorBlocked"] != true {
		t.Errorf("bits 10-12 = %v", q)
	}
	if hex.EncodeToString(b.Contents()) != "030038" { // 3 unused bits, 0x00 0x38
		t.Errorf("bits 10-12 encode as %x", b.Contents())
	}
	// A shorter string takes the defaults for bits it does not carry; a
	// longer one (up to 16) is read, extra bits ignored.
	short := mms.NewBitString(2)
	short.Set(1, true)
	if q := ToJSON(nil, mms.Bits(short), "q").(map[string]any); q["validity"] != "invalid" || q["test"] != false {
		t.Errorf("2-bit quality = %v", q)
	}
	long := mms.NewBitString(16)
	long.Set(11, true)
	long.Set(15, true)
	if q, ok := ToJSON(nil, mms.Bits(long), "q").(map[string]any); !ok || q["test"] != true {
		t.Errorf("16-bit quality = %v", ToJSON(nil, mms.Bits(long), "q"))
	}
}

// Covers: SIG-IPE-1802
func TestTimeQualityMapping(t *testing.T) {
	// 8-1 8.1.3.7 Table 36: bit 0 (MSB of the eighth octet)
	// LeapSecondKnown, 1 ClockFailure, 2 ClockNotSynchronized, 3-7
	// TimeAccuracy; 31 unspecified, 25-30 invalid.
	for q, want := range map[byte]string{
		0x8a: "map[clockFailure:false clockNotSynchronized:false leapSecondsKnown:true timeAccuracy:10]",
		0x1f: "map[clockFailure:false clockNotSynchronized:false leapSecondsKnown:false timeAccuracy:unspecified]",
		0x19: "map[clockFailure:false clockNotSynchronized:false leapSecondsKnown:false timeAccuracy:invalid]",
		0x58: "map[clockFailure:true clockNotSynchronized:false leapSecondsKnown:false timeAccuracy:24]",
		0x20: "map[clockFailure:false clockNotSynchronized:true leapSecondsKnown:false timeAccuracy:0]",
	} {
		if got := fmt.Sprint(TimeQualityJSON(q)); got != want {
			t.Errorf("%#x = %s, want %s", q, got, want)
		}
	}
	at := time.Date(2026, 9, 1, 0, 0, 0, 500_000_000, time.UTC)
	enc := mms.Data{Kind: mms.KUTCTime, Time: mms.UTCTime{T: at, Quality: 0x8a}}.Encode()
	// 91 08: seconds (4 octets), fraction 0x800000 (half a second), quality.
	if hex.EncodeToString(enc) != fmt.Sprintf("9108%08x8000008a", at.Unix()) {
		t.Errorf("utc-time = %x", enc)
	}
	// An untrustworthy time stamp is reported with the quality; a good
	// one is not.
	typ := mms.TypeSpec{Kind: mms.KStructure, Components: []mms.Component{
		{Name: "stVal", Type: mms.TypeSpec{Kind: mms.KBool}},
		{Name: "q", Type: mms.TypeSpec{Kind: mms.KBitString, Size: -13}},
		{Name: "t", Type: mms.TypeSpec{Kind: mms.KUTCTime}}}}
	for q, want := range map[byte]bool{0x0a: false, 0x4a: true, 0x2a: true} {
		d := mms.Structure(mms.Boolean(true), mms.Bits(mms.NewBitString(13)), mms.Data{Kind: mms.KUTCTime, Time: mms.UTCTime{T: at, Quality: q}})
		s := Split(&typ, d, "Pos")
		if _, has := s.Quality["timeQuality"]; has != want || !s.Time.Equal(at) {
			t.Errorf("quality %#x: timeQuality reported %v, time %v", q, has, s.Time)
		}
	}
	// EntryTime is a 6-octet TimeOfDay: milliseconds since midnight and
	// days since 1984-01-01 (8-1 8.1.3.8).
	tod := mms.BinaryTime(time.Date(1984, 1, 2, 0, 0, 1, 0, time.UTC))
	if hex.EncodeToString(tod.Bytes) != "000003e80001" {
		t.Errorf("TimeOfDay = %x", tod.Bytes)
	}
}

// Covers: SIG-IPE-1803
func TestCodedEnumMapping(t *testing.T) {
	// 7-2 6.2.5.2 and 6.2.5.3; 8-1 8.1.2.3: the bit string holds the
	// value, bit 0 the most significant.
	two := mms.TypeSpec{Kind: mms.KBitString, Size: 2}
	for name, bits := range map[string]string{"intermediate-state": "00", "off": "01", "on": "10", "bad-state": "11",
		"stop": "00", "lower": "01", "higher": "10"} {
		d, err := FromJSON(two, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := fmt.Sprint(b2i(d.Bits.Get(0)), b2i(d.Bits.Get(1)))
		if strings.ReplaceAll(got, " ", "") != bits {
			t.Errorf("%s = %s, want %s", name, got, bits)
		}
		if name == "on" || name == "off" || name == "bad-state" || name == "intermediate-state" {
			if back := ToJSON(nil, d, "stVal"); back != name {
				t.Errorf("stVal %s reads back as %v", bits, back)
			}
		}
	}
}

// Covers: SIG-IPE-1804
func TestReportFormatVectors(t *testing.T) {
	// 8-1 Table 41 (OptFlds), Table 37 (TrgOps), Table 38 and 39 (reason
	// codes): bit positions.
	if optSeqNum != 1 || optTimeStamp != 2 || optReason != 3 || optDataSet != 4 || optDataRef != 5 ||
		optBufOvfl != 6 || optEntryID != 7 || optConfRev != 8 || optSegment != 9 {
		t.Error("OptFlds bits differ from 8-1 Table 41")
	}
	if fmt.Sprint(triggerBits) != "map[dchg:1 dupd:3 gi:5 integrity:4 qchg:2]" {
		t.Errorf("TrgOps = %v", triggerBits)
	}
	if strings.Join(reasonNames[1:6], ",") != "dchg,qchg,dupd,integrity,gi" || logReasonNames[6] != "application" {
		t.Errorf("reason codes = %v / %v", reasonNames, logReasonNames)
	}
	// 8-1 17.2.1 Table 74: every optional field, in order, with two of
	// three members included and segmentation.
	opt := mms.NewBitString(10)
	for b := 1; b <= 9; b++ {
		opt.Set(b, true)
	}
	incl := mms.NewBitString(3)
	incl.Set(0, true)
	incl.Set(2, true)
	rc := func(b int) mms.Data { x := mms.NewBitString(7); x.Set(b, true); return mms.Bits(x) }
	at := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	vals := []mms.Data{mms.Visible("rpt1"), mms.Bits(opt), mms.Unsigned(7), mms.BinaryTime(at), mms.Visible("LD1/LLN0$DS1"),
		mms.Boolean(true), mms.Octets([]byte{0, 0, 0, 0, 0, 0, 0, 9}), mms.Unsigned(3), mms.Unsigned(1), mms.Boolean(false),
		mms.Bits(incl), mms.Visible("LD1/MMXU1$MX$Hz"), mms.Visible("LD1/GGIO1$ST$Ind1"), mms.Float32(50), mms.Boolean(true),
		rc(1), rc(5)}
	res := make([]mms.AccessResult, len(vals))
	for i, v := range vals {
		res[i] = mms.AccessResult{Data: v}
	}
	rpt := mms.VMDName("RPT")
	rep, err := ParseReport(mms.InformationReport{Spec: mms.VariableSpec{ListName: &rpt}, Results: res})
	if err != nil {
		t.Fatal(err)
	}
	if rep.RptID != "rpt1" || *rep.SeqNum != 7 || !rep.TimeOfEntry.Equal(at) || rep.DataSet != "LD1/LLN0$DS1" || !rep.BufOvfl ||
		hex.EncodeToString(rep.EntryID) != "0000000000000009" || *rep.ConfRev != 3 || !rep.Segmented || rep.SubSeqNum != 1 || rep.MoreSegments {
		t.Errorf("header = %+v", rep)
	}
	if len(rep.Entries) != 2 || rep.Entries[0].Index != 0 || rep.Entries[1].Index != 2 ||
		rep.Entries[0].Ref != "LD1/MMXU1$MX$Hz" || rep.Entries[1].Value.Bool != true ||
		fmt.Sprint(rep.Entries[0].Reasons, rep.Entries[1].Reasons) != "[dchg] [gi]" {
		t.Errorf("entries = %+v", rep.Entries)
	}
}

// Covers: SIG-IPE-1808
func TestLastApplErrorCorrelation(t *testing.T) {
	// 8-1 Table 110: 28 AddCause values, 0 Unknown to 27
	// Locked-by-other-client.
	if len(addCauses) != 28 || addCauses[0] != "unknown" || addCauses[14] != "1-of-n-control" || addCauses[25] != "none" ||
		addCauses[26] != "inconsistent-parameters" || addCauses[27] != "locked-by-other-client" {
		t.Errorf("AddCause table = %v", addCauses)
	}
	cl := &Client{waiters: map[string]*ctlWaiter{}}
	w, done, _ := cl.wait("LD1/CSWI1$CO$Pos", 6, false)
	defer done()
	lae := func(num uint64, cause int64) mms.InformationReport {
		v := mms.VMDName("LastApplError")
		// CntrlObj, Error, Origin, ctlNum, AddCause (8-1 Table 109).
		return mms.InformationReport{Spec: mms.VariableSpec{Vars: []mms.ObjectName{v}}, Results: []mms.AccessResult{{Data: mms.Structure(
			mms.Visible("LD1/CSWI1$CO$Pos$Oper"), mms.Integer(3), mms.Structure(mms.Integer(3), mms.Octets(nil)), mms.Unsigned(num), mms.Integer(cause))}}}
	}
	cl.controlReport(lae(5, 10)) // another operation's error
	if cause, _ := w.lastCause(); cause != -1 {
		t.Errorf("the LastApplError of ctlNum 5 was taken for 6 (cause %d)", cause)
	}
	cl.controlReport(lae(6, 10))
	cause, applErr := w.lastCause()
	if cause != 10 || applErr != 3 {
		t.Errorf("cause %d error %d", cause, applErr)
	}
	e := &ControlError{Object: "LD1/CSWI1.Pos", Step: "operate", AddCause: cause, ApplError: applErr}
	if !strings.Contains(e.Error(), "blocked-by-interlocking (AddCause 10), operator-test-not-ok") {
		t.Errorf("error = %s", e.Error())
	}
}

// Covers: SIG-IPE-1810
func TestLogEntryMapping(t *testing.T) {
	// 8-1 17.3.3.4.4: per value a journal variable tagged with the data
	// reference, then one tagged "ReasonCode" holding a 7-bit
	// ReasonForInclusionInLog (8.1.3.11, application-trigger bit 6).
	at := time.Date(1984, 1, 2, 0, 0, 1, 0, time.UTC)
	e := LogEntry{EntryID: []byte{0, 0, 0, 0, 0, 0, 0, 5}, Time: at, Values: []LogValue{
		{Ref: "LD1/MMXU1$MX$Hz", Value: mms.Float32(50), Reasons: []string{"dchg", "qchg"}},
		{Ref: "LD1/GGIO1$ST$Ind1$stVal", Value: mms.Boolean(true), Reasons: []string{"application"}}}}
	j := e.JournalEntry()
	if len(j.Variables) != 4 || j.Variables[1].Tag != "ReasonCode" || j.Variables[1].Value.Bits.NBits != 7 ||
		hex.EncodeToString(j.Variables[1].Value.Bits.Bits) != "60" || hex.EncodeToString(j.Variables[3].Value.Bits.Bits) != "02" {
		t.Fatalf("journal entry = %+v", j)
	}
	body := mms.ReadJournalResponse([]mms.JournalEntry{j}, false)
	be, _, _ := mms.Parse(body)
	got, more, err := mms.DecodeReadJournalResponse(be)
	if err != nil || more || len(got) != 1 {
		t.Fatalf("decoded %d, %v, %v", len(got), more, err)
	}
	back := LogEntryFrom(got[0])
	if len(back.Values) != 2 || back.Values[0].Ref != "LD1/MMXU1$MX$Hz" || fmt.Sprint(back.Values[0].Reasons) != "[dchg qchg]" ||
		fmt.Sprint(back.Values[1].Reasons) != "[application]" || !back.Time.Equal(at) {
		t.Errorf("log entry = %+v", back)
	}
}

// Covers: SIG-IPE-1811
func TestFileNameLimit(t *testing.T) {
	if err := checkFileName(strings.Repeat("a", 256)); err == nil {
		t.Error("a 256-octet file name was accepted (8-1 23.1 allows 255)")
	}
	if err := checkFileName("/COMTRADE/" + strings.Repeat("a", 245)); err != nil {
		t.Errorf("a 255-octet file name was refused: %v", err)
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
