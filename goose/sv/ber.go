package sv

import (
	"errors"
	"fmt"
)

// A minimal BER reader and writer for the savPdu (IEC 61850-9-2 A.2,
// ISO/IEC 8825-1): definite lengths only, identifier octets kept as read.

type tlv struct {
	tag []byte // identifier octets
	val []byte // contents
	raw []byte // the whole element
}

// first is the first identifier octet.
func (t tlv) first() byte { return t.tag[0] }

func (t tlv) constructed() bool { return t.tag[0]&0x20 != 0 }

var errTruncated = errors.New("sv: BER element runs past its container")

// readTLV reads one element from b and returns it and the rest.
func readTLV(b []byte) (tlv, []byte, error) {
	if len(b) < 2 {
		return tlv{}, nil, errTruncated
	}
	i := 1
	if b[0]&0x1f == 0x1f {
		// High tag number form: 9-2 uses none, but an extension after
		// the "..." of Table 14 may; it is read so it can be skipped.
		for {
			if i >= len(b) || i > 4 {
				return tlv{}, nil, errTruncated
			}
			c := b[i]
			i++
			if c&0x80 == 0 {
				break
			}
		}
	}
	if i >= len(b) {
		return tlv{}, nil, errTruncated
	}
	tag := b[:i]
	l := int(b[i])
	i++
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 {
			return tlv{}, nil, errors.New("sv: indefinite BER length")
		}
		if n > 3 || i+n > len(b) {
			return tlv{}, nil, errTruncated
		}
		l = 0
		for k := 0; k < n; k++ {
			l = l<<8 | int(b[i])
			i++
		}
	}
	if l > len(b)-i {
		return tlv{}, nil, errTruncated
	}
	return tlv{tag: tag, val: b[i : i+l], raw: b[:i+l]}, b[i+l:], nil
}

// readAll splits contents into elements.
func readAll(b []byte) ([]tlv, error) {
	var out []tlv
	for len(b) > 0 {
		t, rest, err := readTLV(b)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		b = rest
	}
	return out, nil
}

// appendLen appends a definite length in the shortest form.
func appendLen(dst []byte, n int) []byte {
	switch {
	case n < 0x80:
		return append(dst, byte(n))
	case n <= 0xff:
		return append(dst, 0x81, byte(n))
	case n <= 0xffff:
		return append(dst, 0x82, byte(n>>8), byte(n))
	default:
		return append(dst, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
}

// appendTLV appends tag, length and the concatenated contents.
func appendTLV(dst []byte, tag byte, content ...[]byte) []byte {
	n := 0
	for _, c := range content {
		n += len(c)
	}
	dst = append(dst, tag)
	dst = appendLen(dst, n)
	for _, c := range content {
		dst = append(dst, c...)
	}
	return dst
}

// berUint encodes v as a BER INTEGER's contents (two's complement,
// shortest form, a leading 0 when the top bit would be set).
func berUint(v uint64) []byte {
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

// parseBerUint reads a non-negative BER INTEGER of at most 64 bits.
func parseBerUint(b []byte) (uint64, error) {
	if len(b) == 0 {
		return 0, errors.New("an INTEGER with no contents")
	}
	if b[0]&0x80 != 0 {
		return 0, errors.New("a negative INTEGER")
	}
	if len(b) > 1 && b[0] == 0 && b[1]&0x80 == 0 {
		// BER requires the shortest form (ISO/IEC 8825-1 8.3.2).
		return 0, errors.New("an INTEGER with a redundant leading octet")
	}
	if len(b) > 9 || (len(b) == 9 && b[0] != 0) {
		return 0, fmt.Errorf("an INTEGER of %d octets", len(b))
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v, nil
}
