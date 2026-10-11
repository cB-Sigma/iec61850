// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package goose

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Subscription supervises one subscribed GOOSE control block, as a
// subscriber (and its LGOS supervision) does: it checks that a message
// belongs to the control block and configuration expected (GoCBRef, DatSet,
// ConfRev, the number of entries), refuses messages that need
// commissioning (NdsCom) and, unless AcceptSimulated, simulated ones (the
// simulation bit of IEC 61850-8-1 C.2.4 / the Ed. 2.1 header), classifies
// the arrival by stNum and sqNum (Classify), and tracks the time allowed to
// live: a stream from which no message came within the last message's TAL
// has expired (IEC 61850-8-1 18.1.2.5, a subscriber's loss detection).
type Subscription struct {
	// GoCBRef is the control block reference expected ("LD/LLN0$GO$name").
	GoCBRef string
	// DatSet, ConfRev and Entries, when set, are checked against each
	// message (0 or "" not checked).
	DatSet  string
	ConfRev uint32
	Entries int
	// AcceptSimulated takes messages with the simulation bit set (a
	// subscriber in test mode, LPHD.Sim true).
	AcceptSimulated bool

	mu       sync.Mutex
	seen     bool
	st, sq   uint32
	last     time.Time
	deadline time.Time
}

// Errors of Accept: the message is not taken.
var (
	ErrOtherControlBlock  = errors.New("goose: the message is from another control block")
	ErrConfiguration      = errors.New("goose: the message does not match the configuration expected")
	ErrNeedsCommissioning = errors.New("goose: the publisher needs commissioning (NdsCom)")
	ErrSimulated          = errors.New("goose: a simulated message and the subscription is not in test mode")
)

// Accept checks a decoded GOOSE frame received at now. A message it takes
// returns its arrival (ArrivalOld and ArrivalDuplicate should not be
// applied), whether messages were lost before it, and restarts the time
// allowed to live; a message it refuses returns one of the errors above.
func (s *Subscription) Accept(f *Frame, now time.Time) (Arrival, bool, error) {
	if f == nil || f.GOOSE == nil {
		return 0, false, errors.New("goose: not a GOOSE message")
	}
	g := f.GOOSE
	if s.GoCBRef != "" && g.GoCBRef != s.GoCBRef {
		return 0, false, fmt.Errorf("%w: %s", ErrOtherControlBlock, g.GoCBRef)
	}
	switch {
	case s.DatSet != "" && g.DatSet != s.DatSet:
		return 0, false, fmt.Errorf("%w: data set %s, expected %s", ErrConfiguration, g.DatSet, s.DatSet)
	case s.ConfRev != 0 && g.ConfRev != s.ConfRev:
		return 0, false, fmt.Errorf("%w: confRev %d, expected %d", ErrConfiguration, g.ConfRev, s.ConfRev)
	case s.Entries != 0 && len(g.AllData) != s.Entries:
		return 0, false, fmt.Errorf("%w: %d entries, expected %d", ErrConfiguration, len(g.AllData), s.Entries)
	case g.NdsCom:
		return 0, false, ErrNeedsCommissioning
	case (g.Simulation || f.Simulated) && !s.AcceptSimulated:
		return 0, false, ErrSimulated
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, lost := Classify(s.seen, s.st, s.sq, g.StNum, g.SqNum)
	if a == ArrivalOld {
		return a, false, nil
	}
	s.seen, s.st, s.sq = true, g.StNum, g.SqNum
	s.last = now
	tal := g.TAL
	if tal <= 0 {
		tal = 2 * time.Second
	}
	s.deadline = now.Add(tal)
	return a, lost, nil
}

// Expired reports whether the stream has gone quiet: a message was taken
// and no other came within its time allowed to live.
func (s *Subscription) Expired(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen && now.After(s.deadline)
}

// Deadline is when the stream expires unless another message comes (zero
// before the first one).
func (s *Subscription) Deadline() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deadline
}

// State returns the stNum and sqNum last taken and when.
func (s *Subscription) State() (stNum, sqNum uint32, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st, s.sq, s.last
}
