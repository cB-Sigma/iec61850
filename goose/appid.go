// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package goose

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
)

// APPID is an application identifier (IEC 61850-8-1 C.2.5, IEC 61850-9-2)
// as configured: written in JSON as a number or a "0x…" string. The zero
// value means "not configured"; NewAPPID makes a configured one.
type APPID int

// NewAPPID is the configured application identifier v.
func NewAPPID(v uint16) APPID { return APPID(v) + 1 }

// UnmarshalJSON reads a number or a hexadecimal string up to 0xFFFF.
func (a *APPID) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case float64:
		if x < 0 || x > 0xffff || x != math.Trunc(x) {
			return fmt.Errorf("APPID %v is not 0..0xFFFF", x)
		}
		*a = APPID(x)
	case string:
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(x), "0x"), 16, 16)
		if err != nil {
			return fmt.Errorf("APPID %q is not a hexadecimal number up to 0xFFFF", x)
		}
		*a = APPID(n)
	default:
		return errors.New("APPID is a number or a hexadecimal string")
	}
	*a++ // stored plus one so that 0 means "not set"
	return nil
}

func (a APPID) set() bool     { return a > 0 }
func (a APPID) value() uint16 { return uint16(a - 1) }

// String names the value.
func (a APPID) String() string        { return fmt.Sprintf("0x%04X", a.value()) }
func (a APPID) matches(v uint16) bool { return !a.set() || a.value() == v }

// IsSet reports whether the identifier is configured.
func (a APPID) IsSet() bool { return a.set() }

// Matches reports whether v passes the identifier as a filter (an
// unconfigured one passes every value).
func (a APPID) Matches(v uint16) bool { return a.matches(v) }

// ParseMAC reads an Ethernet MAC address ("" gives nil).
func ParseMAC(s string) (net.HardwareAddr, error) {
	if s == "" {
		return nil, nil
	}
	m, err := net.ParseMAC(s)
	if err != nil || len(m) != 6 {
		return nil, fmt.Errorf("%q is not an Ethernet MAC address", s)
	}
	return m, nil
}

// NextCount is the stNum or sqNum after n; both wrap to 1.
func NextCount(n uint32) uint32 {
	if n == math.MaxUint32 {
		return 1
	}
	return n + 1
}

func next(n uint32) uint32 { return NextCount(n) }
