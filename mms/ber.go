// Package mms is a pure Go MMS (ISO 9506) client and server-side framing
// over the OSI stack IEC 61850-8-1 uses on TCP: TPKT (RFC 1006), COTP
// class 0 (ISO 8073), the ISO session kernel (ISO 8327-1), ISO presentation
// in normal mode (ISO 8823-1) with ACSE (ISO 8650-1), and BER (X.690) for
// every PDU. Written from the standards' public structure; no code is taken
// from other implementations.
package mms

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Elem is one decoded BER element. Tag is the first identifier octet
// (class, constructed bit and tag number, or 0x1f for the high-tag form, in
// which case Num holds the number).
type Elem struct {
	Tag byte
	Num int
	Val []byte
}

// Constructed reports whether the element holds other elements.
func (e Elem) Constructed() bool { return e.Tag&0x20 != 0 }

// Context reports whether e is a context-specific element with number n.
func (e Elem) Context(n int) bool { return e.Tag&0xc0 == 0x80 && e.Num == n }

// Children decodes the contents of a constructed element.
func (e Elem) Children() ([]Elem, error) { return ParseAll(e.Val) }

// ErrTruncated is returned for input that ends inside an element.
var ErrTruncated = errors.New("ber: truncated element")

// Parse decodes one element from b and returns it and the rest of b.
func Parse(b []byte) (Elem, []byte, error) {
	if len(b) < 2 {
		return Elem{}, nil, ErrTruncated
	}
	e := Elem{Tag: b[0], Num: int(b[0] & 0x1f)}
	i := 1
	if e.Num == 0x1f {
		e.Num = 0
		for {
			if i >= len(b) || i > 5 {
				return Elem{}, nil, ErrTruncated
			}
			c := b[i]
			i++
			e.Num = e.Num<<7 | int(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
	}
	if i >= len(b) {
		return Elem{}, nil, ErrTruncated
	}
	l := int(b[i])
	i++
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 {
			return Elem{}, nil, errors.New("ber: indefinite lengths are not used by MMS")
		}
		if n > 3 || i+n > len(b) {
			return Elem{}, nil, ErrTruncated
		}
		l = 0
		for k := 0; k < n; k++ {
			l = l<<8 | int(b[i])
			i++
		}
	}
	if l > len(b)-i {
		return Elem{}, nil, ErrTruncated
	}
	e.Val = b[i : i+l]
	return e, b[i+l:], nil
}

// ParseAll decodes a sequence of elements.
func ParseAll(b []byte) ([]Elem, error) {
	var out []Elem
	for len(b) > 0 {
		e, rest, err := Parse(b)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
		b = rest
	}
	return out, nil
}

// RawElements splits a sequence of elements into their encodings.
func RawElements(b []byte) ([][]byte, error) {
	var out [][]byte
	for len(b) > 0 {
		_, rest, err := Parse(b)
		if err != nil {
			return nil, err
		}
		out = append(out, b[:len(b)-len(rest)])
		b = rest
	}
	return out, nil
}

// T encodes an element with the identifier octet tag around content.
func T(tag byte, content ...[]byte) []byte {
	n := 0
	for _, c := range content {
		n += len(c)
	}
	out := make([]byte, 0, n+6)
	out = append(out, tag)
	out = appendLen(out, n)
	for _, c := range content {
		out = append(out, c...)
	}
	return out
}

// TH encodes an element with a high tag number (class and constructed bits
// in cls, e.g. 0xa0 for a constructed context tag).
func TH(cls byte, num int, content ...[]byte) []byte {
	if num < 31 {
		return T(cls|byte(num), content...)
	}
	var id []byte
	for n := num; n > 0; n >>= 7 {
		id = append([]byte{byte(n & 0x7f)}, id...)
	}
	for i := 0; i < len(id)-1; i++ {
		id[i] |= 0x80
	}
	body := T(0, content...)
	return append(append([]byte{cls | 0x1f}, id...), body[1:]...)
}

func appendLen(b []byte, n int) []byte {
	switch {
	case n < 0x80:
		return append(b, byte(n))
	case n < 0x100:
		return append(b, 0x81, byte(n))
	case n < 0x10000:
		return append(b, 0x82, byte(n>>8), byte(n))
	default:
		return append(b, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
}

// IntBytes is the minimal two's complement form of v.
func IntBytes(v int64) []byte {
	b := []byte{byte(v)}
	for v > 127 || v < -128 {
		v >>= 8
		b = append([]byte{byte(v)}, b...)
	}
	return b
}

// UintBytes is the BER INTEGER contents of an unsigned value.
func UintBytes(v uint64) []byte {
	var b []byte
	for {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
		if v == 0 {
			break
		}
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b
}

// Int encodes an INTEGER with the given tag.
func Int(tag byte, v int64) []byte { return T(tag, IntBytes(v)) }

// Uint encodes a non-negative INTEGER with the given tag.
func Uint(tag byte, v uint64) []byte { return T(tag, UintBytes(v)) }

// Bool encodes a BOOLEAN with the given tag.
func Bool(tag byte, v bool) []byte {
	if v {
		return T(tag, []byte{0xff})
	}
	return T(tag, []byte{0})
}

// Str encodes a string type (VisibleString and friends) with the given tag.
func Str(tag byte, s string) []byte { return T(tag, []byte(s)) }

// DecodeInt reads a two's complement INTEGER's contents.
func DecodeInt(b []byte) (int64, error) {
	if len(b) == 0 || len(b) > 8 {
		return 0, fmt.Errorf("ber: an integer of %d octets", len(b))
	}
	v := int64(int8(b[0]))
	for _, c := range b[1:] {
		v = v<<8 | int64(c)
	}
	return v, nil
}

// DecodeUint reads an INTEGER's contents as unsigned.
func DecodeUint(b []byte) (uint64, error) {
	if len(b) == 0 || len(b) > 9 || (len(b) == 9 && b[0] != 0) {
		return 0, fmt.Errorf("ber: an unsigned integer of %d octets", len(b))
	}
	if b[0]&0x80 != 0 {
		return 0, errors.New("ber: a negative value where an unsigned one is expected")
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v, nil
}

// OID encodes an OBJECT IDENTIFIER's contents from dotted form.
func OID(s string) []byte {
	parts := strings.Split(s, ".")
	n := make([]uint64, len(parts))
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			panic("mms: bad OID " + s)
		}
		n[i] = v
	}
	if len(n) < 2 {
		panic("mms: bad OID " + s)
	}
	out := base128(nil, n[0]*40+n[1])
	for _, v := range n[2:] {
		out = base128(out, v)
	}
	return out
}

func base128(b []byte, v uint64) []byte {
	var tmp []byte
	tmp = append(tmp, byte(v&0x7f))
	for v >>= 7; v > 0; v >>= 7 {
		tmp = append(tmp, byte(v&0x7f)|0x80)
	}
	for i := len(tmp) - 1; i >= 0; i-- {
		b = append(b, tmp[i])
	}
	return b
}

// DecodeOID renders an OBJECT IDENTIFIER's contents in dotted form.
func DecodeOID(b []byte) string {
	var parts []string
	var v uint64
	first := true
	for _, c := range b {
		v = v<<7 | uint64(c&0x7f)
		if c&0x80 != 0 {
			continue
		}
		if first {
			a := min(v/40, 2)
			parts = append(parts, strconv.FormatUint(a, 10), strconv.FormatUint(v-a*40, 10))
			first = false
		} else {
			parts = append(parts, strconv.FormatUint(v, 10))
		}
		v = 0
	}
	return strings.Join(parts, ".")
}

// BitString is a BER BIT STRING value: Bits bits, first bit in the most
// significant bit of the first octet.
type BitString struct {
	Bits  []byte
	NBits int
}

// NewBitString makes an all-zero bit string of n bits.
func NewBitString(n int) BitString { return BitString{Bits: make([]byte, (n+7)/8), NBits: n} }

// Get reports bit i.
func (b BitString) Get(i int) bool {
	if i < 0 || i >= b.NBits || i/8 >= len(b.Bits) {
		return false
	}
	return b.Bits[i/8]&(0x80>>(i%8)) != 0
}

// Set sets or clears bit i.
func (b BitString) Set(i int, v bool) {
	if i < 0 || i >= b.NBits {
		return
	}
	if v {
		b.Bits[i/8] |= 0x80 >> (i % 8)
	} else {
		b.Bits[i/8] &^= 0x80 >> (i % 8)
	}
}

// Contents is the BER contents: the unused-bit count, then the bits.
func (b BitString) Contents() []byte {
	n := (b.NBits + 7) / 8
	out := make([]byte, 1+n)
	out[0] = byte(n*8 - b.NBits)
	copy(out[1:], b.Bits)
	return out
}

// DecodeBitString reads a BIT STRING's contents.
func DecodeBitString(v []byte) (BitString, error) {
	if len(v) == 0 {
		return BitString{}, errors.New("ber: an empty bit string")
	}
	unused := int(v[0])
	if unused > 7 || (len(v) == 1 && unused != 0) {
		return BitString{}, errors.New("ber: a bit string with a bad unused-bit count")
	}
	bits := append([]byte(nil), v[1:]...)
	return BitString{Bits: bits, NBits: len(bits)*8 - unused}, nil
}

func float32Bytes(f float64) []byte {
	u := math.Float32bits(float32(f))
	return []byte{8, byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)}
}

func float64Bytes(f float64) []byte {
	u := math.Float64bits(f)
	out := []byte{11}
	for i := 7; i >= 0; i-- {
		out = append(out, byte(u>>(8*i)))
	}
	return out
}
