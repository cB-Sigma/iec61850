// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package iec61850

import (
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

// Covers: SIG-IPE-1810
func TestQueryLogByTimeSendsBothEnds(t *testing.T) {
	// libiec61850 1.6 rejects a ReadJournal with a start time and no stop
	// time (invalid argument); an open end is sent as the first or last
	// TimeOfDay instead of being left out.
	from := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		from, to, wantFrom, wantTo time.Time
	}{
		{from, time.Time{}, from, logTimeLast},
		{time.Time{}, from, logTimeFirst, from},
		{time.Time{}, time.Time{}, logTimeFirst, logTimeLast},
		{from, from.Add(time.Hour), from, from.Add(time.Hour)},
	} {
		r, err := logByTimeRequest("LD1/LLN0$EventLog", c.from, c.to)
		if err != nil {
			t.Fatal(err)
		}
		if !r.HasStart || !r.HasStop || r.StartEntry != nil || r.Count != 0 || !r.StartTime.Equal(c.wantFrom) || !r.EndTime.Equal(c.wantTo) {
			t.Errorf("%s..%s: %+v", c.from, c.to, r)
		}
		if r.Journal != mms.DomainName("LD1", "LLN0$EventLog") {
			t.Errorf("journal %v", r.Journal)
		}
		// The open ends survive the six-octet TimeOfDay encoding.
		for _, at := range []time.Time{r.StartTime, r.EndTime} {
			back, err := mms.DecodeBinaryTime(mms.TimeOfDay6(at))
			if err != nil || !back.Equal(at) {
				t.Errorf("TimeOfDay of %s reads back as %s %v", at, back, err)
			}
		}
	}
}
