package goose

// Arrival classifies a GOOSE message against the last one accepted from
// the same control block, from its stNum and sqNum (IEC 61850-7-2 Table
// 94: stNum starts at 1 and 0 is reserved; sqNum returns to 0 on a state
// change; IEC 61850-8-1 Figure 10: both skip 0 when they wrap). What a
// subscriber does with out-of-order numbers is a local issue (8-1
// 18.1.2.5.1); ours is spelt out per value.
type Arrival int

const (
	// ArrivalFirst is the first message since the subscription started.
	ArrivalFirst Arrival = iota
	// ArrivalNewState has a later stNum: the data set changed.
	ArrivalNewState
	// ArrivalRetransmission repeats the state with a later sqNum.
	ArrivalRetransmission
	// ArrivalDuplicate repeats the last stNum and sqNum (a frame seen
	// twice, as on a PRP pair without duplicate discard).
	ArrivalDuplicate
	// ArrivalRestart is a publisher starting again: stNum back to 1 with
	// sqNum 0 or 1, or sqNum back to 0 within the same stNum.
	ArrivalRestart
	// ArrivalOld has an earlier stNum, or an earlier sqNum of the same
	// state: it arrived out of order and is not applied.
	ArrivalOld
)

// String names the value.
func (a Arrival) String() string {
	return [...]string{"first", "new state", "retransmission", "duplicate", "restart", "out of order"}[a]
}

// after reports whether counter a comes after b in serial order.
// CountAfter reports whether stNum or sqNum a comes after b, with
// wrap-around.
func CountAfter(a, b uint32) bool { return after(a, b) }

func after(a, b uint32) bool { return int32(a-b) > 0 }

// Classify returns how a message with stNum/sqNum relates to the last
// accepted one (st, sq), and whether counter values were skipped
// (messages lost) on the way.
func Classify(seen bool, st, sq, newSt, newSq uint32) (Arrival, bool) {
	switch {
	case !seen:
		return ArrivalFirst, false
	case newSt == st && newSq == sq:
		return ArrivalDuplicate, false
	case newSt == st && after(newSq, sq):
		return ArrivalRetransmission, newSq != next(sq)
	case newSt == st && newSq == 0:
		return ArrivalRestart, false
	case newSt == st:
		return ArrivalOld, false
	case after(newSt, st):
		return ArrivalNewState, newSt != next(st)
	case newSt == 1 && newSq <= 1:
		// Enabling sends sqNum 0 (8-1 Figure 10) or 1 (recommended by
		// 7-2 Table 94); a later sqNum of stNum 1 is a late message.
		return ArrivalRestart, false
	}
	return ArrivalOld, false
}
