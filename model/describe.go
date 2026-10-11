package model

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// terms are our plain-word renderings of the name terms that recur in
// data object names (IEC 61850-7-4 Ed. 2.1 Clause 4 builds names from
// them). Terms not listed fall back to the abbreviation meanings of
// data/text.yaml (names checked against the 7-4 NSD).
var terms = map[string]string{
	"A": "current", "Acc": "accuracy", "Act": "active", "Alm": "alarm", "Amp": "current", "An": "analogue", "Ang": "angle", "Av": "average",
	"Beh": "behaviour", "Blk": "block", "Brk": "breaker", "CB": "circuit breaker", "Cap": "capability", "Cf": "crest factor", "Chg": "change",
	"Chr": "characteristic", "Clc": "calculation", "Cls": "close", "Cnt": "count", "Crv": "curve", "Ctl": "control", "Cur": "current",
	"DExt": "de-excitation", "Dl": "delay", "Del": "delta", "Dev": "deviation", "Dif": "difference", "Dir": "direction", "Dmd": "demand",
	"Dsc": "discrepancy", "EE": "external equipment", "Ena": "enable", "End": "end", "Evn": "even", "Evt": "event", "Exp": "expired",
	"Ext": "external", "Flt": "fault", "Flw": "flow", "Fwd": "forward", "Gnd": "ground", "Gr": "group", "Health": "health", "Hi": "high",
	"Hz": "frequency", "In": "input", "Ind": "indication", "Ins": "insulation", "Intv": "interval", "Key": "key", "Lev": "level",
	"Lin": "line", "Lo": "low", "Loc": "local", "Lod": "load", "Max": "maximum", "Min": "minimum", "Mir": "mirror", "Mod": "mode",
	"Mot": "motor", "Mth": "method", "Mult": "multiplier", "Nam": "name", "Net": "net", "Neut": "neutral", "Ng": "negative", "Nom": "nominal",
	"Num": "number", "Nxt": "next", "Odd": "odd", "Oil": "oil", "Op": "operate", "Opn": "open", "Out": "output", "Ov": "over", "Pct": "percent",
	"PF": "power factor", "Per": "period", "Ph": "phase", "PhV": "phase to ground voltage", "Plt": "plate", "PNV": "phase to neutral voltage",
	"Pos": "position", "PPV": "phase to phase voltage", "Pres": "pressure", "Prm": "permissive", "Ps": "positive", "Pwr": "power",
	"Rch": "reach", "Ref": "reference", "Res": "residual", "Rf": "reference", "Rs": "reset", "Rte": "rate", "Rtg": "rating", "Rv": "reverse",
	"Rx": "receive", "Sel": "select", "Seq": "sequence", "Set": "setting", "Spd": "speed", "Spt": "setpoint", "Src": "source", "St": "status",
	"Sta": "station", "Str": "start", "Sub": "sub", "Sup": "supply", "Sw": "switch", "Syn": "synchronisation", "T": "time", "Thd": "total harmonic distortion",
	"Tm": "time", "Tmh": "time in hours", "Tmms": "time in milliseconds", "Tmp": "temperature", "Tot": "total", "Tr": "trip", "Trk": "tracking",
	"Tx": "transmit", "Typ": "type", "Un": "under", "V": "voltage", "VA": "apparent power", "VAr": "reactive power", "Val": "value",
	"W": "active power", "Wh": "active energy", "VArh": "reactive energy", "VAh": "apparent energy", "Wrn": "warning", "Z": "impedance",
	"Zer": "zero", "Zn": "zone",
}

// Words spells a data object name out in plain words by splitting it into
// known terms (the longest-term split with the fewest unknown characters).
func (m *Model) Words(name string) string {
	type cell struct {
		cost  int
		parts []string
	}
	n := len(name)
	best := make([]*cell, n+1)
	best[0] = &cell{}
	lookup := func(t string) (string, bool) {
		if w, ok := terms[t]; ok {
			return w, true
		}
		if w, ok := m.Abbrev[t]; ok {
			return strings.ToLower(w), true
		}
		if _, err := strconv.Atoi(t); err == nil {
			return t, true
		}
		return "", false
	}
	for i := 0; i < n; i++ {
		if best[i] == nil {
			continue
		}
		for j := i + 1; j <= n && j-i <= 8; j++ {
			w, ok := lookup(name[i:j])
			cost := best[i].cost + 1
			if !ok {
				if j-i != 1 {
					continue
				}
				w, cost = name[i:j], best[i].cost+10
			}
			if best[j] == nil || cost < best[j].cost {
				best[j] = &cell{cost: cost, parts: append(append([]string(nil), best[i].parts...), w)}
			}
		}
	}
	return strings.Join(best[n].parts, " ")
}

// Description is a data object explained for people.
type Description struct {
	LNClass, LNTitle, DataObject, CDC string
	// Words is the name spelt out; Kind the CDC's category.
	Words, Kind string
	// Enum lists the literals of an enumerated data object.
	Enum     string
	Literals []string
	// Mandatory reports presence M for non-derived statistics.
	Mandatory, Transient, Multi bool
	Section                     string
}

// String gives a one-line explanation.
func (d Description) String() string {
	s := fmt.Sprintf("%s.%s: %s (%s, %s)", d.LNClass, d.DataObject, d.Words, d.CDC, d.Kind)
	if d.Enum != "" {
		s += " values " + strings.Join(d.Literals, ", ")
	}
	if d.LNTitle != "" {
		s += " in " + d.LNTitle
	}
	return s
}

// Describe explains data object do of an LN class (an instance number on
// the data object is accepted).
func (m *Model) Describe(lnClass, do string) (Description, error) {
	l, ok := m.LNs[lnClass]
	if !ok {
		return Description{}, fmt.Errorf("%w: %s", ErrUnknownLNClass, lnClass)
	}
	d, ok := l.DataObject(do)
	if !ok {
		return Description{}, fmt.Errorf("%w: %s.%s", ErrUnknownDO, lnClass, do)
	}
	out := Description{LNClass: lnClass, LNTitle: l.Title, DataObject: do, CDC: d.CDC, Words: m.Words(d.Name), Enum: d.Enum,
		Mandatory: d.Mandatory(false), Transient: d.Transient, Multi: d.Multi(), Section: d.Section}
	if c, ok := m.CDCs[d.CDC]; ok {
		out.Kind = c.Kind
	}
	if e, ok := m.Enums[d.Enum]; ok {
		for _, it := range e.Items {
			out.Literals = append(out.Literals, it.Name)
		}
	}
	return out, nil
}

// UnitName returns the SIUnitKind literal of a unit value ("V" for 29);
// the dimensionless unit 1 has the empty literal.
func (m *Model) UnitName(siUnit int) (string, bool) {
	return m.Enums["SIUnitKind"].Literal(siUnit)
}

// MultiplierName returns the MultiplierKind literal of an exponent ("k"
// for 3, "" for 0).
func (m *Model) MultiplierName(mult int) (string, bool) {
	return m.Enums["MultiplierKind"].Literal(mult)
}

// UnitSymbol joins multiplier and unit ("kV" for 3, 29). Deprecated unit
// literals are given as the standard prints them.
func (m *Model) UnitSymbol(siUnit, mult int) (string, error) {
	u, ok := m.UnitName(siUnit)
	if !ok {
		return "", fmt.Errorf("iec61850 model: unknown SIUnit %d", siUnit)
	}
	p, ok := m.MultiplierName(mult)
	if !ok {
		return "", fmt.Errorf("iec61850 model: unknown multiplier %d", mult)
	}
	return p + u, nil
}

// ParseUnit finds SIUnit and multiplier values for a symbol such as "kV",
// "MW", "Hz" or "°C" (the unit alone first, so "min" is minutes and "m"
// metres rather than milli).
func (m *Model) ParseUnit(sym string) (siUnit, mult int, err error) {
	units := m.Enums["SIUnitKind"]
	for _, it := range units.Items {
		if it.Name == sym && sym != "" {
			return it.Value, 0, nil
		}
	}
	mults := m.Enums["MultiplierKind"]
	cands := make([]EnumItem, 0, len(mults.Items))
	cands = append(cands, mults.Items...)
	sort.Slice(cands, func(i, j int) bool { return len(cands[i].Name) > len(cands[j].Name) })
	for _, p := range cands {
		if p.Name == "" || !strings.HasPrefix(sym, p.Name) {
			continue
		}
		for _, it := range units.Items {
			if it.Name != "" && it.Name == sym[len(p.Name):] {
				return it.Value, p.Value, nil
			}
		}
	}
	return 0, 0, fmt.Errorf("iec61850 model: unknown unit %q", sym)
}
