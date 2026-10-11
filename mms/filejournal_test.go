package mms

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// Covers: SIG-IPE-1810
func TestReadJournalPDUs(t *testing.T) {
	// ISO 9506-2:2003 23.2: journalName [0] ObjectName, entryToStartAfter
	// [5] {timeSpecification [0] TimeOfDay, entrySpecification [1] OCTET
	// STRING}, under the readJournal tag [65].
	name := DomainName("LD1", "LLN0$GeneralLog")
	at := time.Date(1984, 1, 2, 0, 0, 1, 0, time.UTC)
	r := ReadJournalRequest{Journal: name, AfterTime: at, AfterEntry: []byte{0, 0, 0, 0, 0, 0, 0, 4}, HasAfter: true}
	want := "bf412e" + "a018" + "a116" + "1a034c4431" + "1a0f" + hex.EncodeToString([]byte("LLN0$GeneralLog")) +
		"a512" + "8006000003e80001" + "81080000000000000004"
	if got := hex.EncodeToString(r.Encode()); got != want {
		t.Errorf("request = %s\nwant      %s", got, want)
	}
	// Range by time and by number of entries: [1] {startingTime [0]}, [2]
	// {numberOfEntries [1]}.
	r = ReadJournalRequest{Journal: name, StartTime: at, HasStart: true, Count: 3, HasStop: true, Variables: []string{"ReasonCode"}}
	e, _, _ := Parse(r.Encode())
	back, err := DecodeReadJournal(e)
	if err != nil || back.Journal != name || !back.StartTime.Equal(at) || back.Count != 3 || len(back.Variables) != 1 || back.HasAfter {
		t.Errorf("decoded = %+v, %v", back, err)
	}
	if !strings.Contains(hex.EncodeToString(r.Encode()), "a1088006000003e80001"+"a203810103"+"a40c1a0a") {
		t.Errorf("range = %x", r.Encode())
	}
	// A response: a data entry, an event entry, an annotation; moreFollows.
	entries := []JournalEntry{
		{EntryID: []byte{5}, Time: at, Variables: []JournalVariable{{Tag: "LD1/MMXU1$MX$Hz", Value: Float32(50)}}},
		{EntryID: []byte{6}, Time: at, Event: &JournalEvent{Condition: DomainName("LD1", "LLN0$LG$lcb01"), State: 2}},
		{EntryID: []byte{7}, Time: at, Annotation: "restart"},
	}
	body := ReadJournalResponse(entries, true)
	be, _, _ := Parse(body)
	got, more, err := DecodeReadJournalResponse(be)
	if err != nil || !more || len(got) != 3 || got[0].Variables[0].Value.Float != 50 || got[1].Event.State != 2 ||
		got[1].Event.Condition != DomainName("LD1", "LLN0$LG$lcb01") || got[2].Annotation != "restart" {
		t.Errorf("response = %+v %v %v", got, more, err)
	}
	// JournalEntry: entryIdentifier [0], originatingApplication [1],
	// entryContent [2] {occurrenceTime [0], data [2] {listOfVariables [1]
	// {SEQUENCE {variableTag [0], valueSpecification [1] Data}}}}.
	if !strings.HasPrefix(hex.EncodeToString(body), "bf41") || !strings.Contains(hex.EncodeToString(body), "800105a1023000a2") {
		t.Errorf("response = %x", body)
	}
}

// Covers: SIG-IPE-1811
func TestFileDirectoryExplicitList(t *testing.T) {
	// listOfDirectoryEntry is [0] without IMPLICIT in a module whose tag
	// default is explicit: [0] { SEQUENCE { DirectoryEntry... } }. Found
	// against libiec61850 1.6.2, which sends this form; we had sent and
	// expected the entries directly inside [0].
	entry := func(name string, size byte) string {
		inner := "a0" + hex.EncodeToString([]byte{byte(2 + len(name)), 0x19, byte(len(name))}) + hex.EncodeToString([]byte(name)) +
			"a103" + "8001" + hex.EncodeToString([]byte{size})
		return "30" + hex.EncodeToString([]byte{byte(len(inner) / 2)}) + inner
	}
	e1, e2 := entry("a.txt", 5), entry("b", 7)
	list := e1 + e2
	seq := "30" + hex.EncodeToString([]byte{byte(len(list) / 2)}) + list
	explicit := "a0" + hex.EncodeToString([]byte{byte(len(seq) / 2)}) + seq
	got := hex.EncodeToString(FileDirectoryResponse([]DirectoryEntry{{Name: "a.txt", FileAttributes: FileAttributes{Size: 5}},
		{Name: "b", FileAttributes: FileAttributes{Size: 7}}}, false))
	if want := "bf4d" + hex.EncodeToString([]byte{byte(len(explicit) / 2)}) + explicit; got != want {
		t.Errorf("FileDirectory response = %s, want %s", got, want)
	}
	for name, content := range map[string]string{
		"explicit, two":        explicit,
		"explicit, empty":      "a0023000",
		"legacy implicit, two": "a0" + hex.EncodeToString([]byte{byte(len(list) / 2)}) + list,
		"legacy implicit, one": "a0" + hex.EncodeToString([]byte{byte(len(e1) / 2)}) + e1,
	} {
		b, _ := hex.DecodeString("bf4d" + hex.EncodeToString([]byte{byte(len(content) / 2)}) + content)
		be, _, err := Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		entries, _, err := DecodeFileDirectoryResponse(be)
		want := 2
		switch name {
		case "explicit, empty":
			want = 0
		case "legacy implicit, one":
			want = 1
		}
		if err != nil || len(entries) != want || (want > 0 && (entries[0].Name != "a.txt" || entries[0].Size != 5)) ||
			(want == 2 && (entries[1].Name != "b" || entries[1].Size != 7)) {
			t.Errorf("%s: %+v %v", name, entries, err)
		}
	}
}

// Covers: SIG-IPE-1811
func TestFilePDUs(t *testing.T) {
	mod := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	// Annex D: fileDirectory [77] {fileSpecification [0] FileName,
	// continueAfter [1] FileName}; a FileName is SEQUENCE OF
	// GraphicString.
	req := FileDirectoryRequest("/COMTRADE/", "/COMTRADE/a")
	if hex.EncodeToString(req) != "bf4d1d"+"a00c190a"+hex.EncodeToString([]byte("/COMTRADE/"))+"a10d190b"+hex.EncodeToString([]byte("/COMTRADE/a")) {
		t.Errorf("FileDirectory request = %x", req)
	}
	e, _, _ := Parse(req)
	if spec, after, err := DecodeFileDirectory(e); spec != "/COMTRADE/" || after != "/COMTRADE/a" || err != nil {
		t.Errorf("decoded %q %q %v", spec, after, err)
	}
	body := FileDirectoryResponse([]DirectoryEntry{{Name: "/COMTRADE/f1.cfg", FileAttributes: FileAttributes{Size: 1500, LastModified: mod}}}, true)
	be, _, _ := Parse(body)
	list, more, err := DecodeFileDirectoryResponse(be)
	if err != nil || !more || len(list) != 1 || list[0].Name != "/COMTRADE/f1.cfg" || list[0].Size != 1500 || !list[0].LastModified.Equal(mod) {
		t.Errorf("FileDirectory response = %+v %v %v", list, more, err)
	}
	// FileOpen [72] {fileName [0], initialPosition [1]}; response {frsmID
	// [0], fileAttributes [1] {sizeOfFile [0], lastModified [1]}}.
	if got := hex.EncodeToString(FileOpenRequest("/a", 0)); got != "bf48"+"09"+"a004"+"19022f61"+"810100" {
		t.Errorf("FileOpen request = %s", got)
	}
	oe, _, _ := Parse(FileOpenRequest("/a", 7))
	if n, p, err := DecodeFileOpen(oe); n != "/a" || p != 7 || err != nil {
		t.Errorf("FileOpen decoded %q %d %v", n, p, err)
	}
	// FileRead [73] and FileClose [74] are the FRSM identifier; FileRead's
	// moreFollows defaults to TRUE.
	if hex.EncodeToString(FRSMRequest(SvcFileRead, 3)) != "9f490103" || hex.EncodeToString(FRSMRequest(SvcFileClose, 3)) != "9f4a0103" {
		t.Errorf("FRSM requests = %x %x", FRSMRequest(SvcFileRead, 3), FRSMRequest(SvcFileClose, 3))
	}
	if hex.EncodeToString(FileReadResponse([]byte{1}, true)) != "bf49038001"+"01" || hex.EncodeToString(FileReadResponse(nil, false)) != "bf4905800081010"+"0" {
		t.Errorf("FileRead responses = %x %x", FileReadResponse([]byte{1}, true), FileReadResponse(nil, false))
	}
	// FileDelete [76] is the FileName; ObtainFile [46] {sourceFile [1],
	// destinationFile [2]} (tag numbers above 30 take the high-tag form).
	if hex.EncodeToString(FileDeleteRequest("/a")) != "bf4c04"+"19022f61" {
		t.Errorf("FileDelete = %x", FileDeleteRequest("/a"))
	}
	if hex.EncodeToString(ObtainFileRequest("/s", "/d")) != "bf2e0c"+"a1041902"+hex.EncodeToString([]byte("/s"))+"a2041902"+hex.EncodeToString([]byte("/d")) {
		t.Errorf("ObtainFile = %x", ObtainFileRequest("/s", "/d"))
	}
	for s, want := range map[string]time.Time{"20260901120000Z": mod, "20260901120000.500Z": mod.Add(500 * time.Millisecond), "20260901120000": mod, "bad": {}} {
		if got := ParseGeneralizedTime(s); !got.Equal(want) {
			t.Errorf("%s = %v", s, got)
		}
	}
}
