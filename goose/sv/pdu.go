package sv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// savPdu and ASDU tags (Table 14, Figure A.6).
const (
	tagSavPdu   = 0x60 // [APPLICATION 0] IMPLICIT SEQUENCE
	tagNoASDU   = 0x80
	tagSecurity = 1 // [1] ANY OPTIONAL: 0x81 or 0xA1
	tagSeqASDU  = 0xA2
	tagASDU     = 0x30

	tagSvID       = 0x80
	tagDatSet     = 0x81
	tagSmpCnt     = 0x82
	tagConfRev    = 0x83
	tagRefrTm     = 0x84
	tagSmpSynch   = 0x85
	tagSmpRate    = 0x86
	tagSample     = 0x87
	tagSmpMod     = 0x88
	tagGmIdentity = 0x89
)

// MaxVisString is the size of VisString129 (svID) and of an
// ObjectReference (datSet) (Table 14).
const MaxVisString = 129

// SmpSynch values (clause 9, Annex C.3.4).
const (
	SynchInternal = 0 // not synchronised to the synchronisation device
	SynchLocal    = 1 // synchronised to a device not globally synchronised
	SynchGlobal   = 2 // synchronised to a globally synchronised device
)

// SynchClass is how a received smpSynch reads (clause 9, C.3.4).
type SynchClass int

// SynchClass values.
const (
	ClassInternal SynchClass = iota
	ClassLocal
	ClassGlobal
	// ClassReserved: 3, 4 and 255, which neither edition assigns (F-1076).
	ClassReserved
)

// String names the value.
func (c SynchClass) String() string {
	return [...]string{"internal", "local", "global", "reserved"}[c]
}

// ClassifySynch reads a received smpSynch: 0, 1 and 2 as defined; 5 to
// 254 (local clock identities of the 2011 edition) as local (C.3.4).
func ClassifySynch(v uint8) SynchClass {
	switch {
	case v <= SynchGlobal:
		return SynchClass(v)
	case v >= 5 && v <= 254:
		return ClassLocal
	}
	return ClassReserved
}

// SmpMod values (Table 9).
type SmpMod uint16

// SmpMod values.
const (
	SmpPerPeriod SmpMod = 0 // samples per nominal period (default)
	SmpPerSecond SmpMod = 1
	SecPerSample SmpMod = 2
)

// Timestamp is the 8-octet IEC 61850-8-1 UtcTime of refrTm: seconds
// since 1970, a 24-bit fraction of a second and the time quality octet.
type Timestamp struct {
	Seconds  uint32
	Fraction uint32 // 24 bits, units of 2^-24 s
	Quality  uint8
}

// TimestampOf converts t (fraction truncated to 2^-24 s).
func TimestampOf(t time.Time, quality uint8) Timestamp {
	return Timestamp{Seconds: uint32(t.Unix()), Fraction: uint32(uint64(t.Nanosecond()) << 24 / 1_000_000_000), Quality: quality}
}

// Time is the instant (nanoseconds rounded down).
func (t Timestamp) Time() time.Time {
	return time.Unix(int64(t.Seconds), int64(uint64(t.Fraction&0xFFFFFF)*1_000_000_000>>24)).UTC()
}

// Bytes is the 8-octet form.
func (t Timestamp) Bytes() []byte {
	b := binary.BigEndian.AppendUint32(nil, t.Seconds)
	return append(b, byte(t.Fraction>>16), byte(t.Fraction>>8), byte(t.Fraction), t.Quality)
}

func parseTimestamp(b []byte) Timestamp {
	return Timestamp{Seconds: binary.BigEndian.Uint32(b), Fraction: uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6]), Quality: b[7]}
}

// ASDU is one sampled value buffer (Table 14). Optional components are
// nil when absent.
type ASDU struct {
	SvID       string
	DatSet     *string
	SmpCnt     uint16
	ConfRev    uint32
	RefrTm     *Timestamp
	SmpSynch   uint8
	SmpRate    *uint16
	Sample     []byte // the data set values (Tables 15, 21)
	SmpMod     *SmpMod
	GmIdentity *[8]byte
}

// SavPDU is the savPdu. noASDU is len(ASDUs).
type SavPDU struct {
	// Security is the whole security element (identifier, length,
	// contents) or nil; IEC 62351-6 gives its contents (F-1071).
	Security []byte
	ASDUs    []ASDU
}

// DecodePDU reads a savPdu that fills the whole APDU.
func DecodePDU(apdu []byte) (*SavPDU, error) {
	top, rest, err := readTLV(apdu)
	if err != nil {
		return nil, fmt.Errorf("savPdu: %w", err)
	}
	if len(rest) != 0 {
		// 5.3.3.4.3: Length and the APDU must agree.
		return nil, fmt.Errorf("savPdu: %d octets after the savPdu inside Length", len(rest))
	}
	if len(top.tag) != 1 || top.first() != tagSavPdu {
		return nil, fmt.Errorf("savPdu: tag %#x, want 0x60", top.first())
	}
	kids, err := readAll(top.val)
	if err != nil {
		return nil, fmt.Errorf("savPdu: %w", err)
	}
	p := &SavPDU{}
	// SEQUENCE: noASDU, [security], asdu, then extensions ("...").
	k := 0
	if k >= len(kids) || kids[k].first() != tagNoASDU || len(kids[k].tag) != 1 {
		return nil, errors.New("savPdu: noASDU [0] missing")
	}
	n, err := parseBerUint(kids[k].val)
	if err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("savPdu: noASDU not in 1..65535 (%v)", err)
	}
	k++
	if k < len(kids) && kids[k].first()&0xDF == 0x80|tagSecurity && len(kids[k].tag) == 1 {
		p.Security = append([]byte(nil), kids[k].raw...)
		k++
	}
	if k >= len(kids) || kids[k].first() != tagSeqASDU || len(kids[k].tag) != 1 {
		return nil, errors.New("savPdu: asdu [2] SEQUENCE OF missing")
	}
	items, err := readAll(kids[k].val)
	if err != nil {
		return nil, fmt.Errorf("savPdu asdu: %w", err)
	}
	for i, it := range items {
		a, err := decodeASDU(it)
		if err != nil {
			return nil, fmt.Errorf("savPdu ASDU %d: %w", i+1, err)
		}
		p.ASDUs = append(p.ASDUs, a)
	}
	if int(n) != len(p.ASDUs) {
		return nil, fmt.Errorf("savPdu: noASDU %d but %d ASDUs", n, len(p.ASDUs))
	}
	// Elements after asdu are extensions and are skipped.
	return p, nil
}

func fixed(t tlv, size int, name string) error {
	if t.constructed() {
		return fmt.Errorf("%s is constructed", name)
	}
	if len(t.val) != size {
		return fmt.Errorf("%s has %d octets, want %d (Table 14)", name, len(t.val), size)
	}
	return nil
}

func visible(s []byte, name string, max int, empty bool) (string, error) {
	if len(s) > max {
		return "", fmt.Errorf("%s longer than %d", name, max)
	}
	if len(s) == 0 && !empty {
		return "", fmt.Errorf("%s is empty", name)
	}
	for _, c := range s {
		if c < 0x20 || c > 0x7E {
			return "", fmt.Errorf("%s has a character outside VisibleString", name)
		}
	}
	return string(s), nil
}

func decodeASDU(e tlv) (ASDU, error) {
	var a ASDU
	if len(e.tag) != 1 || e.first() != tagASDU {
		return a, fmt.Errorf("tag %#x, want 0x30", e.first())
	}
	kids, err := readAll(e.val)
	if err != nil {
		return a, err
	}
	// Components come in tag order; a tag below the last one read, a
	// repeat or a missing mandatory component is refused. Tags above
	// gmIdentity are extensions and are skipped.
	last := -1
	seen := map[int]bool{}
	for _, k := range kids {
		f := k.first()
		num := int(f & 0x1F)
		if f&0xC0 != 0x80 {
			return a, fmt.Errorf("unexpected element %#x", f)
		}
		if len(k.tag) > 1 {
			num = 31 // high tag number: an extension
		}
		if num <= last && num < 31 {
			return a, fmt.Errorf("component [%d] out of order", num)
		}
		last = num
		seen[num] = true
		if num > 9 {
			continue
		}
		if k.constructed() {
			return a, fmt.Errorf("component [%d] is constructed", num)
		}
		switch f {
		case tagSvID:
			a.SvID, err = visible(k.val, "svID", MaxVisString, false)
		case tagDatSet:
			var s string
			if s, err = visible(k.val, "datSet", MaxVisString, true); err == nil {
				a.DatSet = &s
			}
		case tagSmpCnt:
			if err = fixed(k, 2, "smpCnt"); err == nil {
				a.SmpCnt = binary.BigEndian.Uint16(k.val)
			}
		case tagConfRev:
			if err = fixed(k, 4, "confRev"); err == nil {
				a.ConfRev = binary.BigEndian.Uint32(k.val)
			}
		case tagRefrTm:
			if err = fixed(k, 8, "refrTm"); err == nil {
				t := parseTimestamp(k.val)
				a.RefrTm = &t
			}
		case tagSmpSynch:
			if err = fixed(k, 1, "smpSynch"); err == nil {
				a.SmpSynch = k.val[0]
			}
		case tagSmpRate:
			if err = fixed(k, 2, "smpRate"); err == nil {
				r := binary.BigEndian.Uint16(k.val)
				a.SmpRate = &r
			}
		case tagSample:
			a.Sample = append([]byte(nil), k.val...)
		case tagSmpMod:
			if err = fixed(k, 2, "smpMod"); err == nil {
				m := SmpMod(binary.BigEndian.Uint16(k.val))
				a.SmpMod = &m
			}
		case tagGmIdentity:
			if err = fixed(k, 8, "gmIdentity"); err == nil {
				var g [8]byte
				copy(g[:], k.val)
				a.GmIdentity = &g
			}
		}
		if err != nil {
			return a, err
		}
	}
	for _, n := range []int{0, 2, 3, 5, 7} {
		if !seen[n] {
			return a, fmt.Errorf("mandatory component [%d] missing (Table 14)", n)
		}
	}
	return a, nil
}

// EncodePDU encodes the savPdu, refusing values the grammar does not
// allow.
func EncodePDU(p *SavPDU) ([]byte, error) {
	if p == nil || len(p.ASDUs) < 1 || len(p.ASDUs) > 65535 {
		return nil, errors.New("savPdu: noASDU must be 1..65535")
	}
	parts := [][]byte{appendTLV(nil, tagNoASDU, berUint(uint64(len(p.ASDUs))))}
	if p.Security != nil {
		t, rest, err := readTLV(p.Security)
		if err != nil || len(rest) != 0 || len(t.tag) != 1 || t.first()&0xDF != 0x80|tagSecurity {
			return nil, errors.New("savPdu: security must be one [1] element")
		}
		parts = append(parts, p.Security)
	}
	var seq []byte
	for i, a := range p.ASDUs {
		b, err := encodeASDU(a)
		if err != nil {
			return nil, fmt.Errorf("savPdu ASDU %d: %w", i+1, err)
		}
		seq = append(seq, b...)
	}
	parts = append(parts, appendTLV(nil, tagSeqASDU, seq))
	return appendTLV(nil, tagSavPdu, parts...), nil
}

func encodeASDU(a ASDU) ([]byte, error) {
	if _, err := visible([]byte(a.SvID), "svID", MaxVisString, false); err != nil {
		return nil, err
	}
	parts := [][]byte{appendTLV(nil, tagSvID, []byte(a.SvID))}
	if a.DatSet != nil {
		if _, err := visible([]byte(*a.DatSet), "datSet", MaxVisString, true); err != nil {
			return nil, err
		}
		parts = append(parts, appendTLV(nil, tagDatSet, []byte(*a.DatSet)))
	}
	parts = append(parts,
		appendTLV(nil, tagSmpCnt, binary.BigEndian.AppendUint16(nil, a.SmpCnt)),
		appendTLV(nil, tagConfRev, binary.BigEndian.AppendUint32(nil, a.ConfRev)))
	if a.RefrTm != nil {
		parts = append(parts, appendTLV(nil, tagRefrTm, a.RefrTm.Bytes()))
	}
	parts = append(parts, appendTLV(nil, tagSmpSynch, []byte{a.SmpSynch}))
	if a.SmpRate != nil {
		parts = append(parts, appendTLV(nil, tagSmpRate, binary.BigEndian.AppendUint16(nil, *a.SmpRate)))
	}
	parts = append(parts, appendTLV(nil, tagSample, a.Sample))
	if a.SmpMod != nil {
		parts = append(parts, appendTLV(nil, tagSmpMod, binary.BigEndian.AppendUint16(nil, uint16(*a.SmpMod))))
	}
	if a.GmIdentity != nil {
		parts = append(parts, appendTLV(nil, tagGmIdentity, a.GmIdentity[:]))
	}
	return appendTLV(nil, tagASDU, parts...), nil
}
