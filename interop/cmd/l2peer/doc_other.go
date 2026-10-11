// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// Command l2peer runs only on Linux (raw Ethernet through AF_PACKET); the
// interop tests build it with GOOS=linux and run it in a container.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "l2peer needs Linux (AF_PACKET)")
	os.Exit(2)
}
