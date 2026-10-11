// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package interop runs this module's MMS client, GOOSE and sampled values
// codecs and publishers, and SCL parser against libiec61850 v1.6.2.1
// (github.com/mz-automation/libiec61850, GPLv3, commit 6e7a603c; used only
// as a test peer in a container built from ./peer, nothing of it is
// vendored or distributed). The tests are skipped unless
// SIGMA_IEC61850_INTEROP=1 is set and Docker is running.
package interop

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850"
	"github.com/cB-Sigma/iec61850/mms"
)

// image is the reference peers' image, built from ./peer.
const image = "sigma-iec61850-interop:libiec61850-1.6.2.1-p1"

// needDocker skips the test unless SIGMA_IEC61850_INTEROP=1 is set and
// Docker answers, and builds the peer image when it is missing.
func needDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("SIGMA_IEC61850_INTEROP") != "1" {
		t.Skip("set SIGMA_IEC61850_INTEROP=1 to run the interop tests (needs Docker)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker is not running")
	}
	if exec.Command("docker", "image", "inspect", image).Run() == nil {
		return
	}
	out, err := exec.Command("docker", "build", "-q", "-t", image, "peer").CombinedOutput()
	if err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
}

// freePort returns a TCP port free on the loopback interface.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// peer is a program running in a container: its standard input takes
// commands, its output lines are collected.
type peer struct {
	t     *testing.T
	name  string
	cmd   *exec.Cmd
	stdin io.WriteCloser
	lines chan string

	mu  sync.Mutex
	log []string
}

// startPeer runs `docker run --rm -i --name <unique> <args...>`.
func startPeer(t *testing.T, args ...string) *peer {
	t.Helper()
	p := &peer{t: t, name: fmt.Sprintf("sigma-iec61850-%d", time.Now().UnixNano()), lines: make(chan string, 1<<16)}
	full := append([]string{"run", "--rm", "-i", "--name", p.name}, args...)
	p.cmd = exec.Command("docker", full...)
	var err error
	if p.stdin, err = p.cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	r, w := io.Pipe()
	p.cmd.Stdout, p.cmd.Stderr = w, w
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			p.mu.Lock()
			p.log = append(p.log, line)
			p.mu.Unlock()
			select {
			case p.lines <- strings.TrimPrefix(line, "PEER "):
			default:
			}
		}
	}()
	go func() { _ = p.cmd.Wait(); _ = w.Close() }()
	t.Cleanup(func() {
		_, _ = io.WriteString(p.stdin, "quit\n")
		_ = p.stdin.Close()
		_ = exec.Command("docker", "stop", "-t", "2", p.name).Run()
		if t.Failed() || os.Getenv("SIGMA_IEC61850_INTEROP_LOG") == "1" {
			t.Logf("peer %s output:\n%s", p.name, p.output())
		}
	})
	return p
}

func (p *peer) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.log, "\n")
}

// send writes one command line to the peer.
func (p *peer) send(line string) {
	p.t.Helper()
	if _, err := io.WriteString(p.stdin, line+"\n"); err != nil {
		p.t.Fatalf("peer stdin: %v", err)
	}
}

// expect waits for an output line ("PEER " removed) containing all the
// parts, skipping others, and returns it.
func (p *peer) expect(within time.Duration, parts ...string) string {
	p.t.Helper()
	deadline := time.After(within)
	for {
		select {
		case l := <-p.lines:
			ok := true
			for _, part := range parts {
				if !strings.Contains(l, part) {
					ok = false
					break
				}
			}
			if ok {
				return l
			}
		case <-deadline:
			p.t.Fatalf("no line from %s with %q within %s", p.name, parts, within)
			return ""
		}
	}
}

// tryExpect is expect without failing: ok is false when no line came.
func (p *peer) tryExpect(within time.Duration, parts ...string) (string, bool) {
	deadline := time.After(within)
	for {
		select {
		case l := <-p.lines:
			ok := true
			for _, part := range parts {
				if !strings.Contains(l, part) {
					ok = false
					break
				}
			}
			if ok {
				return l, true
			}
		case <-deadline:
			return "", false
		}
	}
}

// drain discards the lines received so far.
func (p *peer) drain() {
	for {
		select {
		case <-p.lines:
		default:
			return
		}
	}
}

// kv splits a peer line into its key=value fields (a value runs to the
// next space; "values=" takes the rest of the line).
func kv(line string) map[string]string {
	m := map[string]string{}
	if i := strings.Index(line, " values="); i >= 0 {
		m["values"] = line[i+len(" values="):]
		line = line[:i]
	}
	for _, f := range strings.Fields(line) {
		if k, v, ok := strings.Cut(f, "="); ok {
			m[k] = v
		}
	}
	return m
}

// startServer runs a libiec61850 server example on a free loopback port
// and returns a client associated with it.
func startServer(t *testing.T, program string) (*iec61850.Client, *peer, string) {
	t.Helper()
	needDocker(t)
	port := freePort(t)
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:102", port), image, "stdbuf", "-oL", program)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ctx := context.Background()
	var cl *iec61850.Client
	var err error
	for i := 0; i < 100; i++ {
		if cl, err = iec61850.Connect(ctx, addr, mms.DialOptions{Timeout: 2 * time.Second}); err == nil {
			t.Cleanup(func() { cl.Close(context.Background()) })
			return cl, p, addr
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("connecting to %s: %v", program, err)
	return nil, nil, ""
}

// ctxT is a context bounded for one test step.
func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}
