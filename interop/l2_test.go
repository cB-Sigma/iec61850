// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850"
	"github.com/cB-Sigma/iec61850/goose/sv"
	"github.com/cB-Sigma/iec61850/mms"
)

// GOOSE and sampled values run on raw Ethernet, which the Docker host of
// a Mac cannot reach: both sides run in containers on a user-defined
// bridge network, ours as cmd/l2peer built for Linux.

// l2 is a Docker network with our l2peer binary ready to run on it.
type l2 struct {
	t       *testing.T
	network string
	bin     string
}

func newL2(t *testing.T) *l2 {
	t.Helper()
	needDocker(t)
	arch, err := exec.Command("docker", "info", "--format", "{{.Architecture}}").Output()
	if err != nil {
		t.Fatal(err)
	}
	goarch := map[string]string{"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}[strings.TrimSpace(string(arch))]
	if goarch == "" {
		t.Skipf("docker architecture %q", arch)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "l2peer")
	build := exec.Command("go", "build", "-o", bin, "./cmd/l2peer")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building l2peer: %v\n%s", err, out)
	}
	n := fmt.Sprintf("sigma-iec61850-l2-%d", time.Now().UnixNano())
	if out, err := exec.Command("docker", "network", "create", "--driver", "bridge", n).CombinedOutput(); err != nil {
		t.Fatalf("docker network create: %v\n%s", err, out)
	}
	l := &l2{t: t, network: n, bin: bin}
	// Registered before the containers' cleanups, so it runs after them.
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", n).Run() })
	return l
}

// ours runs l2peer in a container on the network.
func (l *l2) ours(args ...string) *peer {
	full := append([]string{"--network", l.network, "--cap-add", "NET_RAW", "-v", l.bin + ":/l2peer:ro", image, "/l2peer"}, args...)
	p := startPeer(l.t, full...)
	return p
}

// theirs runs a libiec61850 program in a container on the network.
func (l *l2) theirs(args ...string) *peer {
	full := append([]string{"--network", l.network, "--cap-add", "NET_RAW", image, "stdbuf", "-oL"}, args...)
	return startPeer(l.t, full...)
}

// ourLine strips our l2peer's prefix.
func ourLine(s string) string { return strings.TrimPrefix(s, "OURS ") }

func wantKV(t *testing.T, line string, want map[string]string) map[string]string {
	t.Helper()
	m := kv(ourLine(line))
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %q, want %q in %s", k, m[k], v, line)
		}
	}
	return m
}

// TestGOOSETheirPublisherOurDecoder: libiec61850's stock
// goose_publisher_example and its GoosePublisher API (gspeer gpub) send;
// goose.Decode reads.
func TestGOOSETheirPublisherOurDecoder(t *testing.T) {
	l := newL2(t)
	dec := l.ours("decode")
	dec.expect(30*time.Second, "OURS READY")

	t.Run("stock example", func(t *testing.T) {
		l.theirs("goose_publisher_example", "eth0")
		for sq := 0; sq < 3; sq++ {
			line := dec.expect(15*time.Second, "OURS goose", "appid=1000", fmt.Sprintf("sqNum=%d ", sq))
			m := wantKV(t, line, map[string]string{"gocbRef": "simpleIOGenericIO/LLN0$GO$gcbAnalogValues",
				"datSet": "simpleIOGenericIO/LLN0$AnalogValues", "stNum": "1", "confRev": "1", "tal": "500", "n": "3", "ndsCom": "false", "test": "false"})
			vals := strings.Split(m["values"], ";")
			if len(vals) != 3 || vals[0] != "int:1234" || !strings.HasPrefix(vals[1], "btime:") || vals[2] != "int:5678" {
				t.Errorf("values %v", vals)
			}
		}
		// The fourth message has a member more (the example's
		// "invalid" message: the data set changed without a new confRev).
		line := dec.expect(5*time.Second, "OURS goose", "appid=1000", "sqNum=3 ")
		wantKV(t, line, map[string]string{"n": "4"})
		if !strings.HasSuffix(line, ";bool:true") {
			t.Errorf("fourth message %s", line)
		}
	})

	t.Run("state changes and retransmissions", func(t *testing.T) {
		pub := l.theirs("gspeer", "gpub", "eth0")
		pub.expect(30*time.Second, "READY")
		dec.drain()
		steps := []struct {
			cmd        string
			st, sq     string
			valsPrefix string
		}{
			{"state 7 1 1.5", "1", "0", "int:7;bool:true;float:1.5;bits:13:0000"},
			{"repeat", "1", "1", "int:7;bool:true;float:1.5;bits:13:0000"},
			{"repeat", "1", "2", "int:7;bool:true;float:1.5;bits:13:0000"},
			{"state -3 0 -0.25", "2", "0", "int:-3;bool:false;float:-0.25;bits:13:4000"},
			{"repeat", "2", "1", "int:-3;bool:false;float:-0.25;bits:13:4000"},
			{"state 100000 1 1e+06", "3", "0", "int:100000;bool:true;float:1e+06;bits:13:0000"},
		}
		for _, s := range steps {
			pub.send(s.cmd)
			line := dec.expect(5*time.Second, "OURS goose", "appid=4097", "stNum="+s.st+" ", "sqNum="+s.sq+" ")
			m := wantKV(t, line, map[string]string{"gocbRef": "SIGMAPEER/LLN0$GO$gcb1", "datSet": "SIGMAPEER/LLN0$DS1", "goID": "peerGoID",
				"confRev": "7", "tal": "2000", "n": "4", "vlan": "0", "prio": "4"})
			if m["values"] != s.valsPrefix {
				t.Errorf("%s: values %q, want %q", s.cmd, m["values"], s.valsPrefix)
			}
		}
	})
}

// TestGOOSEOurPublisherTheirSubscriber: goose.Publisher sends; the stock
// goose_subscriber_example and gspeer gsub (GooseSubscriber) read.
func TestGOOSEOurPublisherTheirSubscriber(t *testing.T) {
	l := newL2(t)

	t.Run("stock example", func(t *testing.T) {
		sub := l.theirs("goose_subscriber_example", "eth0")
		sub.expect(30*time.Second, "Set interface id")
		time.Sleep(500 * time.Millisecond)
		pub := l.ours("gpub", "simpleIOGenericIO/LLN0$GO$gcbAnalogValues", "simpleIOGenericIO/LLN0$AnalogValues", "sigmaGoID", "1000", "01:0c:cd:01:00:01")
		pub.expect(30*time.Second, "OURS READY")
		pub.send("state 1234 1 2.5")
		sub.expect(5*time.Second, "stNum: 1 sqNum: 0")
		sub.expect(2*time.Second, "message is valid")
		line := sub.expect(2*time.Second, "allData:")
		if !strings.Contains(line, "{1234,true,2.5") {
			t.Errorf("their allData %q", line)
		}
		pub.send("state 99 0 -1")
		sub.expect(5*time.Second, "stNum: 2 sqNum: 0")
		line = sub.expect(2*time.Second, "allData:")
		if !strings.Contains(line, "{99,false,-1") {
			t.Errorf("their allData %q", line)
		}
		// Retransmissions of state 2.
		sub.expect(5*time.Second, "stNum: 2 sqNum: 1")
		sub.expect(5*time.Second, "stNum: 2 sqNum: 2")
		pub.send("quit")
	})

	t.Run("gsub", func(t *testing.T) {
		sub := l.theirs("gspeer", "gsub", "eth0", "SIGMAOURS/LLN0$GO$gcb1", "0x1002")
		sub.expect(30*time.Second, "READY")
		pub := l.ours("gpub", "SIGMAOURS/LLN0$GO$gcb1", "SIGMAOURS/LLN0$DS1", "oursGoID", "0x1002", "01:0c:cd:01:00:03")
		pub.expect(30*time.Second, "OURS READY")
		pub.send("state 5 1 0.5")
		line := sub.expect(5*time.Second, "goose stNum=1 sqNum=0 ")
		m := kv(line)
		for k, v := range map[string]string{"confRev": "3", "ndsCom": "0", "test": "0", "valid": "1", "err": "0", "appid": "4098",
			"goID": "oursGoID", "datSet": "SIGMAOURS/LLN0$DS1", "gocbRef": "SIGMAOURS/LLN0$GO$gcb1", "n": "4"} {
			if m[k] != v {
				t.Errorf("%s = %q, want %q in %s", k, m[k], v, line)
			}
		}
		if ttl, _ := strconv.Atoi(m["ttl"]); ttl != 40 {
			t.Errorf("timeAllowedToLive %d, want 40 (twice MinTime)", ttl)
		}
		if ts, _ := strconv.ParseInt(m["ts"], 10, 64); time.Since(time.UnixMilli(ts)).Abs() > time.Minute {
			t.Errorf("timestamp %s", m["ts"])
		}
		if !strings.HasPrefix(m["values"], "{5,true,0.5") {
			t.Errorf("values %q", m["values"])
		}
		// The retransmissions of the first state are not checked one by
		// one: the libiec61850 subscriber sometimes misses sqNum 1, 20 ms
		// after the first frame it receives (likely its receiver binding
		// its raw socket lazily on that first receive). Every
		// retransmission of the second state is checked.
		sub.expect(5*time.Second, "goose stNum=1 sqNum=3 ")
		pub.send("state -8 0 3")
		line = sub.expect(5*time.Second, "goose stNum=2 sqNum=0 ")
		if v := kv(line)["values"]; !strings.HasPrefix(v, "{-8,false,3") || !strings.Contains(v, "01000") {
			// quality: validity invalid is the second bit of 13
			t.Errorf("values %q", v)
		}
		for sq := 1; sq <= 4; sq++ {
			line := sub.expect(5*time.Second, fmt.Sprintf("goose stNum=2 sqNum=%d ", sq))
			if ttl, _ := strconv.Atoi(kv(line)["ttl"]); ttl != 40<<sq && ttl != 1000 {
				t.Errorf("sqNum %d: timeAllowedToLive %d", sq, ttl)
			}
		}
	})
}

// TestGoCBOverMMS: GetGoCBValues and SetGoCBValues (GoEna) of this
// module's client against libiec61850's server_example_goose, with the
// GOOSE it then publishes read by goose.Decode on the Docker network.
func TestGoCBOverMMS(t *testing.T) {
	l := newL2(t)
	dec := l.ours("decode")
	dec.expect(30*time.Second, "OURS READY")
	port := freePort(t)
	startPeer(t, "--network", l.network, "--cap-add", "NET_RAW", "-p", fmt.Sprintf("127.0.0.1:%d:102", port), image,
		"stdbuf", "-oL", "server_example_goose", "--ifc", "eth0")
	var cl *iec61850.Client
	var err error
	for i := 0; i < 100; i++ {
		if cl, err = iec61850.Connect(context.Background(), fmt.Sprintf("127.0.0.1:%d", port), mms.DialOptions{Timeout: 2 * time.Second}); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close(context.Background())
	const ld = "simpleIOGenericIO"
	v, err := cl.GoCBValues(ctxT(t), ld, "gcbEvents")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("gcbEvents: %v", v)
	if v["DatSet"] != ld+"/LLN0$Events3" || fmt.Sprint(v["ConfRev"]) != "2" {
		t.Errorf("GoCB values %v", v)
	}
	if err := cl.EnableGoCB(ctxT(t), ld, "gcbEvents", false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	dec.drain()
	if err := cl.EnableGoCB(ctxT(t), ld, "gcbEvents", true); err != nil {
		t.Fatal(err)
	}
	if v, _ := cl.GoCBValues(ctxT(t), ld, "gcbEvents"); v["GoEna"] != true {
		t.Errorf("GoEna after enabling: %v", v["GoEna"])
	}
	line := dec.expect(10*time.Second, "OURS goose", "gocbRef="+ld+"/LLN0$GO$gcbEvents")
	m := wantKV(t, line, map[string]string{"datSet": ld + "/LLN0$Events3", "confRev": "2", "appid": "4096"}) // SCL APPID 1000 is hexadecimal
	st, _ := strconv.Atoi(m["stNum"])
	// A control changes SPCSO1, a member of Events3: a new state.
	if err := cl.Operate(ctxT(t), iec61850.Ref{LD: ld, LN: "GGIO1", Path: []string{"SPCSO1"}}, true, iec61850.ControlOptions{}); err != nil {
		t.Fatal(err)
	}
	line = dec.expect(10*time.Second, "OURS goose", "gocbRef="+ld+"/LLN0$GO$gcbEvents", "values=bool:true;")
	if m := kv(ourLine(line)); m["sqNum"] != "0" {
		t.Errorf("the new state's first message has sqNum %s", m["sqNum"])
	} else if n, _ := strconv.Atoi(m["stNum"]); n <= st {
		t.Errorf("stNum %d after %d", n, st)
	}
	if err := cl.EnableGoCB(ctxT(t), ld, "gcbEvents", false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	dec.drain()
	time.Sleep(2 * time.Second) // longer than MaxTime
	for {
		select {
		case l := <-dec.lines:
			if strings.Contains(l, "gcbEvents") {
				t.Fatalf("published after GoEna false: %s", l)
			}
			continue
		default:
		}
		break
	}
}

func float32At(b []byte, off int) float64 {
	return float64(math.Float32frombits(binary.BigEndian.Uint32(b[off:])))
}

// TestSVTheirPublisherOurDecoder: the stock sv_publisher_example and
// gspeer svpub (SVPublisher) send; goose.Decode reads the savPdu.
func TestSVTheirPublisherOurDecoder(t *testing.T) {
	l := newL2(t)
	dec := l.ours("decode")
	dec.expect(30*time.Second, "OURS READY")

	t.Run("stock example", func(t *testing.T) {
		l.theirs("sv_publisher_example", "eth0")
		var prev1 = -1
		for i := 0; i < 5; i++ {
			l1 := dec.expect(10*time.Second, "OURS sv", "svID=svpub1 ")
			l2 := dec.expect(2*time.Second, "OURS sv", "svID=svpub2 ")
			m1 := wantKV(t, l1, map[string]string{"appid": "16384", "confRev": "1", "smpSynch": "0", "datSet": ""})
			m2 := kv(ourLine(l2))
			d1, _ := hex.DecodeString(m1["data"])
			d2, _ := hex.DecodeString(m2["data"])
			if len(d1) != 16 || len(d2) != 16 {
				t.Fatalf("data %x %x", d1, d2)
			}
			// asdu2 carries twice asdu1's values; the timestamps match.
			if f1, f2 := float32At(d1, 0), float32At(d2, 0); math.Abs(2*f1-f2) > 1e-2*math.Abs(f2)+1e-3 {
				t.Errorf("FLOAT32 %v and %v", f1, f2)
			}
			if hex.EncodeToString(d1[8:]) != hex.EncodeToString(d2[8:]) {
				t.Errorf("timestamps %x %x", d1[8:], d2[8:])
			}
			cnt, _ := strconv.Atoi(m1["smpCnt"])
			if prev1 >= 0 && cnt != prev1+1 {
				t.Errorf("smpCnt %d after %d", cnt, prev1)
			}
			prev1 = cnt
		}
	})

	t.Run("INT32 and quality", func(t *testing.T) {
		pub := l.theirs("gspeer", "svpub", "eth0")
		pub.expect(30*time.Second, "READY")
		dec.drain()
		pub.send("send 17 100 -200 300000 -4")
		line := dec.expect(5*time.Second, "OURS sv", "svID=peerSV ")
		m := wantKV(t, line, map[string]string{"appid": "16385", "datSet": "SIGMAPEER/LLN0$PhsMeas1", "smpCnt": "17", "confRev": "3", "smpSynch": "2"})
		d, _ := hex.DecodeString(m["data"])
		if len(d) != 32 {
			t.Fatalf("data %x", d)
		}
		for k, want := range []int32{100, -200, 300000, -4} {
			if got := int32(binary.BigEndian.Uint32(d[8*k:])); got != want {
				t.Errorf("value %d: %d, want %d", k, got, want)
			}
		}
		// Quality: good for the first three, questionable for the fourth
		// (libiec61850's QUALITY_VALIDITY_QUESTIONABLE), read with the
		// Table 21 mapping of goose/sv.
		for k := 0; k < 4; k++ {
			q := sv.Quality(binary.BigEndian.Uint32(d[8*k+4:]))
			want := "good"
			if k == 3 {
				want = "questionable"
			}
			if q.String() != want {
				t.Errorf("quality %d: %08x %s, want %s", k, uint32(q), q, want)
			}
		}
	})
}

// TestSVOurPublisherTheirSubscriber: sv.Publisher sends; the stock
// sv_subscriber_example and gspeer svsub (SVSubscriber) read.
func TestSVOurPublisherTheirSubscriber(t *testing.T) {
	l := newL2(t)

	t.Run("stock example", func(t *testing.T) {
		sub := l.theirs("sv_subscriber_example", "eth0")
		sub.expect(30*time.Second, "Set interface id")
		time.Sleep(500 * time.Millisecond)
		pub := l.ours("svpub", "oursSV", "SIGMAOURS/LLN0$PhsMeas1", "0x4000", "01:0c:cd:04:00:01", "float")
		pub.expect(30*time.Second, "OURS READY")
		seen := false
		for try := 0; try < 10 && !seen; try++ {
			pub.send("push 1.5 -2.25")
			_, seen = sub.tryExpect(time.Second, "svID=(oursSV)")
		}
		if !seen {
			t.Fatal("no SV frame reached the subscriber")
		}
		sub.expect(2*time.Second, "dataSet=(SIGMAOURS/LLN0$PhsMeas1)")
		cnt := sub.expect(2*time.Second, "smpCnt: ")
		sub.expect(2*time.Second, "confRev: 1")
		sub.expect(2*time.Second, "DATA[0]: 1.500000")
		sub.expect(2*time.Second, "DATA[1]: -2.250000")
		n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(cnt, "  smpCnt:")))
		pub.send("push 3 4")
		sub.expect(5*time.Second, fmt.Sprintf("smpCnt: %d", n+1))
		sub.expect(2*time.Second, "DATA[0]: 3.000000")
	})

	t.Run("svsub INT32 and quality", func(t *testing.T) {
		sub := l.theirs("gspeer", "svsub", "eth0", "0x4002")
		sub.expect(30*time.Second, "READY")
		pub := l.ours("svpub", "oursSV2", "SIGMAOURS/LLN0$PhsMeas2", "0x4002", "01:0c:cd:04:00:03", "intq")
		pub.expect(30*time.Second, "OURS READY")
		// A frame sent while the receiver thread is still starting is
		// lost; push until one arrives (the sample counter goes on).
		var line string
		for try := 0; try < 10 && line == ""; try++ {
			pub.send("push 11 -22 33 -44")
			line, _ = sub.tryExpect(time.Second, "sv svID=oursSV2 ")
		}
		if line == "" {
			t.Fatal("no SV frame reached the subscriber")
		}
		m := kv(line)
		for k, v := range map[string]string{"datSet": "SIGMAOURS/LLN0$PhsMeas2", "confRev": "1", "smpSynch": "0", "size": "32",
			"i0": "11", "i1": "-22", "i2": "33", "i3": "-44", "q0": "0000"} {
			if m[k] != v {
				t.Errorf("%s = %q, want %q in %s", k, m[k], v, line)
			}
		}
		// Questionable is Table 21 bits 31-30 set, the two least
		// significant bits, which libiec61850 reads as its
		// QUALITY_VALIDITY_QUESTIONABLE.
		if m["q3"] != "0003" {
			t.Errorf("q3 = %s, want libiec61850's QUALITY_VALIDITY_QUESTIONABLE (0003)", m["q3"])
		}
	})
}
