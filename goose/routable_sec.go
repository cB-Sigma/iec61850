package goose

// Secured routable GOOSE/SV: IEC 61850-8-1 Annex J session header with a
// KeyID of a configured key, TimeOfCurrentKey, TimeOfNextKey and the
// initialisation vector, and the MAC after the payload (and padding). The
// security information is normative in IEC 62351-6 (8-1 J.3.2.1), but
// IEC 62351-6:2020 gives no routable wire layout of its own (F-800): the
// MAC field is our reading, a signature element (tag 0x85, a one-octet
// length, the MAC) after the payload and its padding (F-801).
//
//   - HMAC-SHA256 and AES-GMAC cover the SPDU from the session
//     identifier to the end of the padding (8-1 J.3.2.1: the SPDU from
//     its SI, without the HMAC itself).
//   - AES-128-GCM and AES-256-GCM (IEC 62351-6 8.2.2.2, Table 11)
//     encrypt the user payloads (PayloadLength stays in clear, J.3.2.7);
//     the additional authenticated data is the SPDU from the SI to the
//     PayloadLength, and the GCM tag is the MAC (Table 11 c1, c2). No
//     padding is sent or accepted with GCM.

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// sigTag is the tag of the signature (MAC) element after the payload
// (our reading, F-801).
const sigTag = 0x85

// state is the validity of key k at now.
func (s *KeyStore) state(k *SecKey, now time.Time) KeyState {
	switch {
	case !k.From.IsZero() && now.Before(k.From.Add(-keyClockSkew)):
		return KeyNotYet
	case !k.Until.IsZero() && now.After(k.Until.Add(keyClockSkew)):
		if k.Delivered && s.expiredGrace > 0 && now.After(k.Until.Add(s.expiredGrace)) {
			return KeyExpired // IEC 62351-9 8.7.2: the grace for an expired TEK is over
		}
		if cur, _, expired := s.Current(k.APPID.value(), k.DataSet, now); expired && cur == k {
			return KeyExpiredAssumed
		}
		return KeyExpired
	}
	return KeyOK
}

func (s *KeyStore) byID(id uint32) *SecKey {
	for _, k := range s.list() {
		if k.ID == id {
			return k
		}
	}
	return nil
}

// KeyError is a secured SPDU refused for its key; the FrameSec returned
// with it names the key state for the security log.
// KeyError is a refused secured routable SPDU: why, and the security
// event it raises.
type KeyError struct{ Reason, Event string }

// Error describes the failure.
func (e *KeyError) Error() string { return e.Reason }

// openSPDU verifies (and decrypts) the user payloads of a secured SPDU;
// ps is the offset of the first payload octet in b, n the PayloadLength.
func (s *KeyStore) openSPDU(b []byte, h *SPDU, ps, n int, now time.Time) ([]byte, *FrameSec, error) {
	sec := &FrameSec{Routable: true}
	k := s.byID(h.KeyID)
	if k == nil {
		sec.KeyState = KeyUnknown
		return nil, sec, &KeyError{fmt.Sprintf("key %d is not held (IEC 62351-9 GROUP-PULL not built)", h.KeyID), "unknown-key"}
	}
	sec.Key, sec.KeyState = k, s.state(k, now)
	switch sec.KeyState {
	case KeyNotYet:
		return nil, sec, &KeyError{fmt.Sprintf("key %d is not valid yet", k.ID), "key-not-yet-valid"}
	case KeyExpired:
		return nil, sec, &KeyError{fmt.Sprintf("key %d has expired", k.ID), "key-expired"}
	}
	if k.cbc != nil {
		return s.openCBC(b, h, k, sec, ps, n)
	}
	end := ps + n
	t := b[end:]
	padded := false
	if len(t) > 0 && t[0] == paddingTag {
		if len(t) < 2 || int(t[1]) > 32 || len(t) < 2+int(t[1]) {
			return nil, sec, &KeyError{"bad padding after the payload", "malformed"}
		}
		end += 2 + int(t[1])
		t = t[2+int(t[1]):]
		padded = true
	}
	if len(t) < 2 || t[0] != sigTag || int(t[1]) != len(t)-2 {
		return nil, sec, &KeyError{"no signature element after the payload", "malformed"}
	}
	mac := t[2:]
	if k.Encryption == "" {
		if !k.verify(h.IV, b[2:end], mac) {
			return nil, sec, &KeyError{fmt.Sprintf("the MAC does not verify with key %d", k.ID), "mac-failure"}
		}
		return b[ps : ps+n], sec, nil
	}
	if padded || len(h.IV) != ivSize || len(mac) != gcmTagSize {
		return nil, sec, &KeyError{"an encrypted SPDU needs a 16-octet IV and tag and no padding", "malformed"}
	}
	ct := append(append([]byte(nil), b[ps:ps+n]...), mac...)
	pt, err := k.aead.Open(nil, h.IV, ct, b[2:ps])
	if err != nil {
		return nil, sec, &KeyError{fmt.Sprintf("the SPDU does not decrypt with key %d", k.ID), "decrypt-failure"}
	}
	return pt, sec, nil
}

// SealRoutable encodes a secured SPDU with key k: KeyID, TimeOfCurrentKey
// and TimeOfNextKey (seconds, -1 when no new key is scheduled, at most
// 32767) in the session header, a 16-octet IV for AES-GMAC and AES-GCM
// (drawn when iv is nil), the payload encrypted with AES-GCM keys, and
// the signature element.
func SealRoutable(s SPDU, k *SecKey, tock uint32, ttnk int64, iv []byte) ([]byte, error) {
	if k.MAC.Size == 0 {
		return nil, errors.New("a routable SPDU needs a MAC (KeyID other than 0 means HMAC or encryption)")
	}
	s.KeyID, s.TimeOfCurrentKey = k.ID, tock
	s.TimeOfNextKey = uint16(int16(max(-1, min(ttnk, 32767))))
	s.IV = nil
	if k.needsIV() {
		if iv == nil {
			iv = make([]byte, ivSize)
			if _, err := rand.Read(iv); err != nil {
				return nil, err
			}
		}
		s.IV = iv
	}
	b, err := EncodeRoutable(s)
	if err != nil {
		return nil, err
	}
	ps := 6 + int(b[5]) + 4
	n := len(b) - ps
	spduLen := binary.BigEndian.Uint32(b[6:]) + uint32(2+k.MAC.Size)
	if spduLen > maxSPDULength {
		return nil, fmt.Errorf("an SPDU of %d octets (at most %d)", spduLen, maxSPDULength)
	}
	binary.BigEndian.PutUint32(b[6:], spduLen)
	var mac []byte
	if k.cbc != nil {
		return sealCBC(b, k, s.IV, ps, n)
	}
	if k.Encryption != "" {
		sealed := k.aead.Seal(nil, s.IV, b[ps:], b[2:ps])
		copy(b[ps:], sealed[:n])
		mac = sealed[n:]
	} else {
		mac = k.sum(s.IV, b[2:])
	}
	b = append(b, sigTag, byte(len(mac)))
	return append(b, mac...), nil
}

// AES-CBC (Tables 11 and 12, our reading F-821): the user payloads and
// then the padding element (tag 0xAF, its length, that many octets) that
// brings them to whole 16-octet blocks are encrypted under the IV;
// PayloadLength keeps the length of the payloads in clear; the MAC, under
// the key's macKey and the same IV, covers the SPDU from the SI to the
// end of the ciphertext.
func sealCBC(b []byte, k *SecKey, iv []byte, ps, n int) ([]byte, error) {
	pad := 16 - (n+2)%16
	if pad == 16 {
		pad = 0
	}
	pt := append(append([]byte(nil), b[ps:]...), paddingTag, byte(pad))
	for range pad {
		pt = append(pt, byte(pad))
	}
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(k.cbc, iv).CryptBlocks(ct, pt)
	b = append(b[:ps], ct...)
	spduLen := binary.BigEndian.Uint32(b[6:]) + uint32(2+pad+2+k.MAC.Size)
	if spduLen > maxSPDULength {
		return nil, fmt.Errorf("an SPDU of %d octets (at most %d)", spduLen, maxSPDULength)
	}
	binary.BigEndian.PutUint32(b[6:], spduLen)
	mac := k.sum(iv, b[2:])
	b = append(b, sigTag, byte(len(mac)))
	return append(b, mac...), nil
}

func (s *KeyStore) openCBC(b []byte, h *SPDU, k *SecKey, sec *FrameSec, ps, n int) ([]byte, *FrameSec, error) {
	end := len(b) - 2 - k.MAC.Size
	if len(h.IV) != ivSize || end < ps || b[end] != sigTag || int(b[end+1]) != k.MAC.Size {
		return nil, sec, &KeyError{"an AES-CBC SPDU needs a 16-octet IV and a signature element", "malformed"}
	}
	if !k.verify(h.IV, b[2:end], b[end+2:]) {
		return nil, sec, &KeyError{fmt.Sprintf("the MAC does not verify with key %d", k.ID), "mac-failure"}
	}
	ct := b[ps:end]
	if len(ct)%16 != 0 || len(ct) < n+2 {
		return nil, sec, &KeyError{"the AES-CBC ciphertext is not whole blocks holding the payload and padding", "decrypt-failure"}
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(k.cbc, h.IV).CryptBlocks(pt, ct)
	if pt[n] != paddingTag || int(pt[n+1]) != len(pt)-n-2 || pt[n+1] > 32 {
		return nil, sec, &KeyError{"the AES-CBC padding does not decrypt", "decrypt-failure"}
	}
	return pt[:n], sec, nil
}
