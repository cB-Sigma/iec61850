// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package goose_test

import (
	"fmt"
	"net"
	"time"

	"github.com/cB-Sigma/iec61850/goose"
	"github.com/cB-Sigma/iec61850/mms"
)

// Encode a GOOSE frame and decode it again, as a subscriber reading a
// capture would.
func ExampleDecode() {
	dst, _ := net.ParseMAC("01:0c:cd:01:00:01")
	src, _ := net.ParseMAC("00:11:22:33:44:55")
	b := goose.EncodeGOOSE(goose.Frame{Dst: dst, Src: src, VLAN: 0, Priority: 4, APPID: 0x3001, GOOSE: &goose.GOOSE{
		GoCBRef: "IED1LD0/LLN0$GO$gcbTrip", TAL: 2 * time.Second, DatSet: "IED1LD0/LLN0$Trip", GoID: "trip",
		T: time.Unix(1_700_000_000, 0), StNum: 3, SqNum: 0, ConfRev: 1, AllData: []mms.Data{mms.Boolean(true)}}})
	f, err := goose.Decode(b)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("APPID 0x%04X %s stNum %d trip %v\n", f.APPID, f.GOOSE.GoCBRef, f.GOOSE.StNum, f.GOOSE.AllData[0].Bool)
	a, _ := goose.Classify(true, 3, 0, 3, 1)
	fmt.Println(a)
	// Output:
	// APPID 0x3001 IED1LD0/LLN0$GO$gcbTrip stNum 3 trip true
	// retransmission
}
