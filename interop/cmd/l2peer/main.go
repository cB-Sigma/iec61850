// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command l2peer is this module's side of the GOOSE and sampled values
// interop tests: it runs in a Linux container on the same Docker network
// as libiec61850's publishers and subscribers and sends or decodes raw
// Ethernet frames with the goose and goose/sv packages.
//
//	l2peer decode                      print every GOOSE and SV frame
//	l2peer gpub <gocbRef> <datSet> <goID> <appid> <dstMAC>
//	    stdin: state <int32> <0|1> <float32> | quit
//	    data set INT32, BOOLEAN, FLOAT32, quality; retransmits on its own
//	l2peer svpub <svID> <datSet> <appid> <dstMAC> float|intq
//	    stdin: push <v>... | quit   (float: two FLOAT32; intq: four
//	    INT32 and quality pairs, the fourth questionable)
//
// Output lines start "OURS ".
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/iec61850/goose"
	"github.com/cB-Sigma/iec61850/goose/sv"
	"github.com/cB-Sigma/iec61850/mms"
)

var outMu sync.Mutex

func say(format string, a ...any) {
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf("OURS "+format+"\n", a...)
}

// The container's interface on the Docker network.
const iface = "eth0"

// fmtData renders an MMS value compactly for the test to compare.
func fmtData(d mms.Data) string {
	switch d.Kind {
	case mms.KBool:
		return fmt.Sprintf("bool:%v", d.Bool)
	case mms.KInt:
		return fmt.Sprintf("int:%d", d.Int)
	case mms.KUint:
		return fmt.Sprintf("uint:%d", d.Uint)
	case mms.KFloat:
		return fmt.Sprintf("float:%g", d.Float)
	case mms.KBitString:
		return fmt.Sprintf("bits:%d:%s", d.Bits.NBits, hex.EncodeToString(d.Bits.Bits))
	case mms.KUTCTime:
		return fmt.Sprintf("utc:%d", d.Time.T.UnixMilli())
	case mms.KBinaryTime:
		t, _ := mms.DecodeBinaryTime(d.Bytes)
		return fmt.Sprintf("btime:%d", t.UnixMilli())
	case mms.KVisible, mms.KMMSString:
		return "str:" + d.Str
	case mms.KOctets:
		return "oct:" + hex.EncodeToString(d.Bytes)
	case mms.KStructure, mms.KArray:
		parts := make([]string, len(d.Elems))
		for i, e := range d.Elems {
			parts[i] = fmtData(e)
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	return fmt.Sprintf("kind%d", d.Kind)
}

func decode() error {
	// goose.OpenInterface: every multicast frame, the stripped 802.1Q tag
	// restored.
	src, err := goose.OpenInterface(iface, nil)
	if err != nil {
		return err
	}
	defer src.Close()
	say("READY")
	buf := make([]byte, 65536)
	for {
		n, _, err := src.ReadFrame(buf)
		if err != nil {
			return err
		}
		f, err := goose.Decode(append([]byte(nil), buf[:n]...))
		if err != nil {
			et := ""
			if n >= 14 {
				et = hex.EncodeToString(buf[12:14])
			}
			if et == "88b8" || et == "88ba" || et == "8100" {
				say("error ethertype=%s %v frame=%s", et, err, hex.EncodeToString(buf[:n]))
			}
			continue
		}
		switch {
		case f.GOOSE != nil:
			g := f.GOOSE
			vals := make([]string, len(g.AllData))
			for i, d := range g.AllData {
				vals[i] = fmtData(d)
			}
			say("goose appid=%d vlan=%d prio=%d src=%s gocbRef=%s datSet=%s goID=%s stNum=%d sqNum=%d tal=%d confRev=%d ndsCom=%v test=%v t=%d tq=%02x n=%d values=%s",
				f.APPID, f.VLAN, f.Priority, f.Src, g.GoCBRef, g.DatSet, g.GoID, g.StNum, g.SqNum, g.TAL.Milliseconds(), g.ConfRev,
				g.NdsCom, g.Simulation, g.T.UnixMilli(), g.TQuality, g.NumEntries, strings.Join(vals, ";"))
		case f.SV != nil:
			for _, a := range f.SV.ASDUs {
				say("sv appid=%d vlan=%d svID=%s datSet=%s smpCnt=%d confRev=%d smpSynch=%d refrTm=%d data=%s",
					f.APPID, f.VLAN, a.SvID, a.DatSet, a.SmpCnt, a.ConfRev, a.SmpSynch, a.RefrTm.UnixMilli(), hex.EncodeToString(a.SeqData))
			}
		}
	}
}

func gpub(args []string) error {
	if len(args) < 5 {
		return fmt.Errorf("gpub needs gocbRef datSet goID appid dstMAC")
	}
	appid, err := strconv.ParseUint(args[3], 0, 16)
	if err != nil {
		return err
	}
	sink, mac, err := goose.OpenSendInterface(iface)
	if err != nil {
		return err
	}
	defer sink.Close()
	p := &goose.Publication{ID: "interop", GoCBRef: args[0], DataSet: args[1], GoID: args[2], APPID: goose.NewAPPID(uint16(appid)),
		DstMAC: args[4], ConfRev: 3, MinTime: 20 * time.Millisecond, MaxTime: 500 * time.Millisecond,
		Members: []goose.PubMember{{Name: "i", Type: "int32"}, {Name: "b", Type: "boolean"}, {Name: "f", Type: "float32"}, {Name: "q", Type: "quality"}}}
	if err := p.Prepare(); err != nil {
		return err
	}
	p.SetSource(mac)
	pub := goose.NewPublisher(p)
	var mu sync.Mutex
	enabled := false
	out := func(frame []byte) {
		st, sq := pub.State()
		if err := sink.WriteFrame(frame); err != nil {
			say("error send %v", err)
			return
		}
		say("sent stNum=%d sqNum=%d", st, sq)
	}
	go func() {
		for {
			time.Sleep(5 * time.Millisecond)
			mu.Lock()
			if enabled {
				if f, ok := pub.Due(time.Now()); ok {
					out(f)
				}
			}
			mu.Unlock()
		}
	}()
	say("READY")
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "quit":
			return nil
		case "state":
			if len(fields) != 4 {
				say("error state needs three values")
				continue
			}
			i, _ := strconv.Atoi(fields[1])
			f, _ := strconv.ParseFloat(fields[3], 64)
			q := "good"
			if i < 0 {
				q = "invalid"
			}
			mu.Lock()
			frame, _, err := pub.Set(map[string]any{"i": float64(i), "b": fields[2] == "1", "f": f, "q": q}, time.Now())
			if err != nil {
				say("error %v", err)
			} else if !enabled {
				enabled = true
				out(pub.Enable(time.Now()))
			} else if frame != nil {
				out(frame)
			}
			mu.Unlock()
		}
	}
	return nil
}

func svpub(args []string) error {
	if len(args) < 5 {
		return fmt.Errorf("svpub needs svID datSet appid dstMAC float|intq")
	}
	appid, err := strconv.ParseUint(args[2], 0, 16)
	if err != nil {
		return err
	}
	dst, err := net.ParseMAC(args[3])
	if err != nil {
		return err
	}
	sink, mac, err := goose.OpenSendInterface(iface)
	if err != nil {
		return err
	}
	defer sink.Close()
	var types []sv.Type
	switch args[4] {
	case "float":
		types = []sv.Type{sv.Float32, sv.Float32}
	case "intq":
		for k := 0; k < 4; k++ {
			types = append(types, sv.Int32, sv.QualityType)
		}
	default:
		return fmt.Errorf("unknown data set %s", args[4])
	}
	cb := sv.MSVCB{Name: "MSVCB01", MsvID: args[0], DatSet: args[1], ConfRev: 1, SmpRate: 80, OptFlds: sv.OptDataSetName,
		NoASDU: 1, DstAddress: sv.PhyComAddr{Addr: dst, Priority: 4, VID: 0, APPID: uint16(appid)}}
	pub, err := sv.NewPublisher(sv.Config{CB: cb, Src: mac, Types: types})
	if err != nil {
		return err
	}
	say("READY")
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "quit":
			return nil
		case "push":
			var vals []any
			for k, s := range fields[1:] {
				if args[4] == "float" {
					f, _ := strconv.ParseFloat(s, 64)
					vals = append(vals, float32(f))
				} else {
					n, _ := strconv.Atoi(s)
					q := sv.Quality(0)
					if k == 3 {
						q = sv.ValidityQuestionable
					}
					vals = append(vals, int32(n), q)
				}
			}
			frame, err := pub.Push(time.Now(), vals, sv.Sync{SmpSynch: 0})
			if err != nil {
				say("error %v", err)
				continue
			}
			if frame != nil {
				if err := sink.WriteFrame(frame); err != nil {
					say("error send %v", err)
					continue
				}
				say("sent %d", len(frame))
			}
		}
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: l2peer decode | gpub ... | svpub ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "decode":
		err = decode()
	case "gpub":
		err = gpub(os.Args[2:])
	case "svpub":
		err = svpub(os.Args[2:])
	default:
		err = fmt.Errorf("unknown mode %s", os.Args[1])
	}
	if err != nil {
		say("error %v", err)
		os.Exit(1)
	}
}
