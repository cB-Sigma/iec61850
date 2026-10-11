package goose

import "math"

// Aggregator turns a sampled values stream into one result per window:
// the RMS of each channel, the worst sample quality, and the frequency
// measured on one channel from its rising zero crossings (with linear
// interpolation between samples).
type Aggregator struct {
	idx    []int
	scale  []float64
	window int
	rate   int
	freq   int // position in idx, -1 none

	n      int
	sumSq  []float64
	worst  []int // 0 good, 1 questionable, 2 invalid, 3 missing
	test   []bool
	pos    float64 // sample position of the latest sample
	prev   float64
	havePv bool
	cross  []float64
}

// Result is one window's aggregate.
type Result struct {
	RMS       []float64
	Quality   []string
	Frequency float64 // NaN when fewer than two crossings were seen
}

// NewAggregator aggregates channels at the given sequence-of-data
// positions, each value multiplied by its scale, over window samples of a
// stream of rate samples per second; freq is the position (in idx) of the
// frequency channel or -1.
func NewAggregator(idx []int, scale []float64, window, rate, freq int) *Aggregator {
	a := &Aggregator{idx: idx, scale: scale, window: window, rate: rate, freq: freq}
	a.Reset()
	return a
}

// Reset starts a new window (after a gap in the stream).
func (a *Aggregator) Reset() {
	a.n = 0
	a.sumSq = make([]float64, len(a.idx))
	a.worst = make([]int, len(a.idx))
	a.test = make([]bool, len(a.idx))
	a.havePv = false
	a.cross = a.cross[:0]
}

func rank(q uint32) int {
	switch q & 3 {
	case 0:
		return 0
	case 3:
		return 1
	}
	return 2
}

// Add takes one ASDU's samples; step is how far its smpCnt moved since
// the previous one (1 without loss). It returns a result when the window
// is complete.
func (a *Aggregator) Add(s []Sample, step int) (Result, bool) {
	a.pos += float64(step)
	for i, k := range a.idx {
		if k >= len(s) {
			a.worst[i] = 3
			continue
		}
		v := s[k].Float() * a.scale[i]
		a.sumSq[i] += v * v
		if r := rank(s[k].Quality); r > a.worst[i] {
			a.worst[i] = r
		}
		if s[k].Quality&(1<<11) != 0 {
			a.test[i] = true
		}
		if i == a.freq {
			if a.havePv && a.prev < 0 && v >= 0 {
				// Crossing between the previous and this sample.
				frac := -a.prev / (v - a.prev)
				a.cross = append(a.cross, a.pos-float64(step)+frac*float64(step))
			}
			a.prev, a.havePv = v, true
		}
	}
	a.n++
	if a.n < a.window {
		return Result{}, false
	}
	r := Result{RMS: make([]float64, len(a.idx)), Quality: make([]string, len(a.idx)), Frequency: math.NaN()}
	for i := range a.idx {
		r.RMS[i] = round(math.Sqrt(a.sumSq[i]/float64(a.n)), 6)
		r.Quality[i] = [...]string{"good", "questionable", "invalid", "missing"}[a.worst[i]]
		if a.test[i] {
			r.Quality[i] += ",test"
		}
	}
	if len(a.cross) >= 2 {
		span := a.cross[len(a.cross)-1] - a.cross[0]
		if span > 0 {
			r.Frequency = round(float64(len(a.cross)-1)*float64(a.rate)/span, 4)
		}
	}
	// The next window keeps the frequency channel's continuity.
	prev, have := a.prev, a.havePv
	a.Reset()
	a.prev, a.havePv = prev, have
	return r, true
}

func round(v float64, digits int) float64 {
	p := math.Pow(10, float64(digits))
	return math.Round(v*p) / p
}
