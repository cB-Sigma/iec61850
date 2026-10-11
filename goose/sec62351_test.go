package goose

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

// IEC 62351-6:2020 has no worked examples or test vectors: the
// primitives are checked against RFC 4231 (HMAC-SHA-256), the GCM
// specification's test cases (McGrew and Viega, used by NIST SP 800-38D
// validation) and the ISO/IEC 13239 CRC check value; the frame layouts
// are assembled by hand from the clauses.

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Covers: SIG-SEC-702
func TestHMACSHA256RFC4231(t *testing.T) {
	for _, c := range []struct {
		name, key, data, mac string
		alg                  string
	}{
		{"TC1", strings.Repeat("0b", 20), hex.EncodeToString([]byte("Hi There")),
			"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "hmac-sha256"},
		{"TC2", hex.EncodeToString([]byte("Jefe")), hex.EncodeToString([]byte("what do ya want for nothing?")),
			"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "hmac-sha256"},
		// Truncation to 128 bits (RFC 4231 4.6), as HMAC-SHA256-128 sends.
		{"TC5", strings.Repeat("0c", 20), hex.EncodeToString([]byte("Test With Truncation")),
			"a3b6167473100ee06e0c796c2955552b", "hmac-sha256-128"},
		{"TC6", strings.Repeat("aa", 131), hex.EncodeToString([]byte("Test Using Larger Than Block-Size Key - Hash Key First")),
			"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", "hmac-sha256"},
	} {
		k := &SecKey{MAC: macAlgs[c.alg], secret: hx(t, c.key)}
		if got := hex.EncodeToString(k.sum(nil, hx(t, c.data))); got != c.mac {
			t.Errorf("%s = %s, want %s", c.name, got, c.mac)
		}
	}
	// HMAC-SHA256-80 is the leftmost ten octets.
	k := &SecKey{MAC: macAlgs["hmac-sha256-80"], secret: hx(t, strings.Repeat("0b", 20))}
	if got := hex.EncodeToString(k.sum(nil, []byte("Hi There"))); got != "b0344c61d8db38535ca8" {
		t.Errorf("HMAC-SHA256-80 = %s", got)
	}
}

// The GCM specification's test cases (96-bit, 64-bit and 480-bit IVs;
// the last two exercise the GHASH-derived counter a 16-octet IV uses)
// and GMAC as GCM without plaintext.
//
// Covers: SIG-SEC-702
func TestAESGCMVectors(t *testing.T) {
	p4 := "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
	a4 := "feedfacedeadbeeffeedfacedeadbeefabaddad2"
	for _, c := range []struct{ name, k, iv, p, a, c, t string }{
		{"TC1 (GMAC)", strings.Repeat("00", 16), strings.Repeat("00", 12), "", "", "", "58e2fccefa7e3061367f1d57a4e7455a"},
		{"TC2", strings.Repeat("00", 16), strings.Repeat("00", 12), strings.Repeat("00", 16), "", "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"},
		{"TC4", "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", p4, a4,
			"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", "5bc94fbc3221a5db94fae95ae7121a47"},
		{"TC5 (64-bit IV)", "feffe9928665731c6d6a8f9467308308", "cafebabefacedbad", p4, a4,
			"61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598", "3612d2e79e3b0785561be14aaca2fccb"},
		{"TC6 (480-bit IV)", "feffe9928665731c6d6a8f9467308308",
			"9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b", p4, a4,
			"8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5", "619cc5aefffe0bfa462af43c1699d050"},
		{"TC13 (AES-256 GMAC)", strings.Repeat("00", 32), strings.Repeat("00", 12), "", "", "", "530f8afbc74536b9a963b4f1c4cb738b"},
		{"TC14 (AES-256)", strings.Repeat("00", 32), strings.Repeat("00", 12), strings.Repeat("00", 16), "", "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919"},
	} {
		blk, err := aes.NewCipher(hx(t, c.k))
		if err != nil {
			t.Fatal(err)
		}
		iv := hx(t, c.iv)
		g, err := cipher.NewGCMWithNonceSize(blk, len(iv))
		if err != nil {
			t.Fatal(err)
		}
		out := g.Seal(nil, iv, hx(t, c.p), hx(t, c.a))
		if got, want := hex.EncodeToString(out), c.c+c.t; got != want {
			t.Errorf("%s = %s, want %s", c.name, got, want)
		}
	}
	// AES-GMAC-64 is the leftmost eight octets of the tag (SP 800-38D).
	k, err := NewSecKey(KeySpec{KeyID: 1, MAC: "aes-gmac-64", Key: strings.Repeat("00", 16)}, false)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 16)
	blk, _ := aes.NewCipher(make([]byte, 16))
	g, _ := cipher.NewGCMWithNonceSize(blk, 16)
	if got, full := k.sum(iv, []byte("x")), g.Seal(nil, iv, nil, []byte("x")); !bytes.Equal(got, full[:8]) {
		t.Errorf("GMAC-64 %x is not the leftmost octets of %x", got, full)
	}
}

// Covers: SIG-SEC-703
func TestCRC16ISO13239(t *testing.T) {
	if c := crc16([]byte("123456789")); c != 0x906e {
		t.Errorf("check value = %#04x, want 0x906e", c)
	}
}

var (
	hmacKey = strings.Repeat("11", 32)
	gmacKey = strings.Repeat("22", 32)
)

// ap is an APPID setting (stored plus one, 0 meaning unset).
func ap(v uint16) APPID { return APPID(v) + 1 }

func testKeys(t *testing.T, extra ...KeySpec) *KeyStore {
	t.Helper()
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	until := from.Add(48 * time.Hour)
	keys := append([]KeySpec{
		{KeyID: 0x0a0b0c0d, APPID: ap(0x3002), MAC: "hmac-sha256-128", Key: hmacKey, ValidFrom: &from, ValidUntil: &until},
		{KeyID: 7, APPID: ap(0x4001), MAC: "aes-gmac-64", Key: gmacKey},
	}, extra...)
	ks, err := NewKeyStore(KeyStoreOptions{Keys: keys, AllowMACNone: true}, from)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func securedTestFrame(t *testing.T, st uint32) []byte {
	t.Helper()
	return EncodeGOOSE(Frame{Dst: net1, Src: net2, VLAN: 0, Priority: 4, APPID: 0x3001, GOOSE: &GOOSE{GoCBRef: "L/LLN0$GO$g", TAL: time.Second,
		DatSet: "L/LLN0$DS", GoID: "g", T: time.Unix(1_788_000_000, 0), StNum: st, ConfRev: 1, AllData: []mms.Data{mms.Boolean(true)}}})
}

var (
	net1 = []byte{0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01}
	net2 = []byte{0x02, 0, 0, 0, 0, 1}
)

// The Layer 2 extension of 8.2 assembled by hand: Reserved 1 carries the
// extension length (Figure 5, S bit kept), Reserved 2 the ISO/IEC 13239
// CRC of octets 1 to 8, the Length field still counts 8 + m (Figure 6),
// and after the APDU comes [0] { [4] AuthenticationValue { version 1,
// timeOfCurrentKey, timeOfNextKey, keyID }, [5] mAC } with the MAC over
// Ethertype to the end of the extension without the mAC.
//
// Covers: SIG-SEC-700, SIG-SEC-701, SIG-SEC-703, SIG-SEC-704
func TestLayer2ExtensionLayout(t *testing.T) {
	k, err := NewSecKey(KeySpec{KeyID: 0x0a0b0c0d, MAC: "hmac-sha256-128", Key: hmacKey}, false)
	if err != nil {
		t.Fatal(err)
	}
	plain := securedTestFrame(t, 1)
	plain[22] |= 0x80 // S bit (simulation) must survive
	out, err := SecureL2(plain, k, 1_788_000_000, -1, nil)
	if err != nil {
		t.Fatal(err)
	}
	i := 16 // Ethertype after the 802.1Q tag
	length := int(binary.BigEndian.Uint16(out[i+4:]))
	if length != len(plain)-i-2 {
		t.Errorf("Length = %d, want 8 + m = %d", length, len(plain)-i-2)
	}
	ext := out[i+2+length:]
	wantExt := hx(t, `a0 26
		a4 12  80 01 01  81 04 6a 92 b7 00  82 01 ff  84 04 0a 0b 0c 0d
		85 10`)
	if !bytes.Equal(ext[:len(wantExt)], wantExt) || len(ext) != len(wantExt)+16 {
		t.Fatalf("extension = %x\nwant      %x + 16 MAC octets", ext, wantExt)
	}
	r1 := binary.BigEndian.Uint16(out[i+6:])
	if r1 != 0x8000|uint16(len(ext)) {
		t.Errorf("Reserved 1 = %#04x, want S and length %d", r1, len(ext))
	}
	if r2 := binary.BigEndian.Uint16(out[i+8:]); r2 != crc16(out[i:i+8]) {
		t.Errorf("Reserved 2 = %#04x, want the CRC of octets 1 to 8", r2)
	}
	m := hmac.New(sha256.New, hx(t, hmacKey))
	m.Write(out[i : len(out)-16-2])
	if !bytes.Equal(m.Sum(nil)[:16], out[len(out)-16:]) {
		t.Errorf("mAC is not HMAC-SHA256-128 over Ethertype..extension without the mAC")
	}
	// The decoder reads it back.
	f, err := Decode(out)
	if err != nil || f.Sec == nil || !f.Sec.CRCOK || f.Sec.Auth.KeyID != 0x0a0b0c0d || f.Sec.Auth.TimeToNextKey != -1 ||
		f.Sec.Auth.TimeOfCurrentKey != 1_788_000_000 || f.Sec.Auth.Version != 1 || !f.Simulated || f.GOOSE.StNum != 1 || len(f.Sec.MAC) != 16 {
		t.Fatalf("decoded %+v %+v, %v", f, f.Sec, err)
	}
	// Frames with an extension longer than the frame are refused.
	bad := append([]byte(nil), out[:len(out)-1]...)
	if f, err := Decode(bad); err != nil || f.Sec.Malformed == "" {
		t.Errorf("a truncated extension: %+v, %v", f, err)
	}
	// Encryption on Layer 2 is out of scope (8.2.2.2).
	gk, _ := NewSecKey(KeySpec{KeyID: 3, MAC: "aes-gmac-128", Encryption: EncAES128GCM, Key: strings.Repeat("33", 16)}, false)
	if _, err := SecureL2(plain, gk, 0, -1, nil); err == nil {
		t.Error("Layer 2 encryption accepted")
	}
}

// Subscriber security checks (6.2.1.2 and 6.2.2.3.1) on Layer 2 frames.
//
// Covers: SIG-SEC-705, SIG-SEC-706, SIG-SEC-707, SIG-SEC-708
func TestLayer2SubscriberChecks(t *testing.T) {
	ks := testKeys(t, KeySpec{KeyID: 99, APPID: ap(0x3003), MAC: "none", Key: ""})
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	mk := func(id uint32, st uint32) []byte {
		k := ks.byID(id)
		b := securedTestFrame(t, st)
		binary.BigEndian.PutUint16(b[18:], k.APPID.Value()) // the key's APPID
		out, err := SecureL2(b, k, 0, -1, nil)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	check := func(b []byte, expect bool) (*SecKey, KeyState, *SecFailure) {
		f, err := Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		return ks.Check(expect, f, f.GOOSE.DatSet, now)
	}
	good := mk(0x0a0b0c0d, 1)
	if k, st, fail := check(good, true); fail != nil || k.ID != 0x0a0b0c0d || st != KeyOK {
		t.Errorf("HMAC frame: %v %v", st, fail)
	}
	if _, _, fail := check(mk(7, 1), true); fail != nil {
		t.Errorf("GMAC-64 frame: %v", fail)
	}
	// Expected but absent: failure. Not expected: whatever is there is
	// not verified and not a failure. Neither: no failure.
	plain := securedTestFrame(t, 1)
	if _, _, fail := check(plain, true); fail == nil || fail.Event != "missing-authentication" {
		t.Errorf("missing AuthenticationValue: %v", fail)
	}
	tampered := append([]byte(nil), good...)
	tampered[40] ^= 1
	if _, _, fail := check(tampered, false); fail != nil {
		t.Errorf("unexpected AuthenticationValue failed: %v", fail)
	}
	if _, _, fail := check(plain, false); fail != nil {
		t.Errorf("no AuthenticationValue, none expected: %v", fail)
	}
	if _, _, fail := check(tampered, true); fail == nil || fail.Event != "mac-failure" {
		t.Errorf("tampered APDU: %v", fail)
	}
	hdr := append([]byte(nil), good...)
	hdr[19] ^= 1 // APPID low octet: the CRC no longer matches
	if _, _, fail := check(hdr, true); fail == nil || fail.Event != "crc-failure" {
		t.Errorf("tampered header: %v", fail)
	}
	// A key that is not held, one that expired while a newer one exists,
	// and MAC-None (testing only) when allowed.
	unk := append([]byte(nil), good...)
	idx := bytes.Index(unk, []byte{0x84, 0x04, 0x0a, 0x0b, 0x0c, 0x0d})
	unk[idx+5] = 0x0e
	if _, st, fail := check(unk, true); fail == nil || fail.Event != "unknown-key" || st != KeyUnknown {
		t.Errorf("unknown key: %v", fail)
	}
	if _, _, fail := check(mk(99, 1), true); fail != nil {
		t.Errorf("MAC-None with allowMacNone: %v", fail)
	}
	late := now.Add(72 * time.Hour)
	f, _ := Decode(good)
	if _, st, fail := ks.Check(true, f, "", late); fail != nil || st != KeyExpiredAssumed {
		t.Errorf("last delivered key after expiry: %v %v", st, fail)
	}
	early := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	if _, _, fail := ks.Check(true, f, "", early); fail == nil || fail.Event != "key-not-yet-valid" {
		t.Errorf("key before validFrom: %v", fail)
	}
	// Extensions that do not follow 8.2.2.1.
	for name, ext := range map[string]string{
		"empty Reserved":   "a0 02 a1 00",
		"auth without mAC": "a0 0e a4 0c 80 01 01 81 01 00 82 01 ff 84 01 01",
		"not [0]":          "30 00",
		"no keyID":         "a0 0f a4 09 80 01 01 81 01 00 82 01 ff 85 02 00 00",
	} {
		b := securedTestFrame(t, 1)
		e := hx(t, ext)
		binary.BigEndian.PutUint16(b[22:], uint16(len(e)))
		binary.BigEndian.PutUint16(b[24:], crc16(b[16:24]))
		b = append(b, e...)
		f, err := Decode(b)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if f.Sec.Malformed == "" {
			t.Errorf("%s: read as %+v", name, f.Sec)
		}
	}
}

// Secured routable SPDUs (8-1 Annex J with the IEC 62351-6 fields): the
// session header carries the KeyID, TimeOfCurrentKey, TimeOfNextKey and
// a 16-octet IV; HMAC and AES-GMAC cover the SPDU from the SI to the end
// of the payload (and padding); AES-GCM encrypts the payload with the
// header up to PayloadLength as additional data and the tag as the MAC.
//
// Covers: SIG-SEC-710, SIG-SEC-711, SIG-SEC-712, SIG-SEC-713
func TestRoutableSecuredSPDU(t *testing.T) {
	g1 := goosePDU(t, 1, false)
	spdu := SPDU{SI: SIGOOSE, Number: 3, Version: SessionVersion, Payloads: []Payload{{Tag: PayloadGOOSE, APPID: 0x3001, APDU: g1}}}
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	ks, err := NewKeyStore(KeyStoreOptions{Keys: []KeySpec{
		{KeyID: 11, MAC: "hmac-sha256-80", Key: hmacKey},
		{KeyID: 12, MAC: "aes-gmac-128", Key: strings.Repeat("22", 16)},
		{KeyID: 13, MAC: "aes-gmac-128", Encryption: EncAES128GCM, Key: strings.Repeat("33", 16)},
		{KeyID: 14, MAC: "aes-gmac-128", Encryption: EncAES256GCM, Key: strings.Repeat("44", 32)},
	}}, now)
	if err != nil {
		t.Fatal(err)
	}
	iv := hx(t, "000102030405060708090a0b0c0d0e0f")
	for _, id := range []uint32{11, 12, 13, 14} {
		k := ks.byID(id)
		b, err := SealRoutable(spdu, k, 1_788_000_000, -1, iv)
		if err != nil {
			t.Fatal(err)
		}
		pv := int(b[5])
		h := b[6:]
		if kid := binary.BigEndian.Uint32(h[16:]); kid != id || binary.BigEndian.Uint16(h[14:]) != 0xffff ||
			binary.BigEndian.Uint32(h[10:]) != 1_788_000_000 {
			t.Errorf("key %d: header %x", id, h[:pv])
		}
		if k.needsIV() != (h[20] == 16) {
			t.Errorf("key %d: IV length %d", id, h[20])
		}
		sig := b[len(b)-2-k.MAC.Size:]
		if sig[0] != 0x85 || int(sig[1]) != k.MAC.Size {
			t.Errorf("key %d: signature element %x", id, sig[:2])
		}
		if spduLen := binary.BigEndian.Uint32(b[6:]); int(spduLen) != len(b)-10 {
			t.Errorf("key %d: SPDU length %d for %d octets after it", id, spduLen, len(b)-10)
		}
		ps := 6 + pv + 4
		if enc := bytes.Contains(b[ps:], g1); enc == (k.Encryption != "") {
			t.Errorf("key %d: payload in clear = %v", id, enc)
		}
		switch k.Encryption {
		case "":
			mac := k.sum(h[21:21+int(h[20])], b[2:len(b)-2-k.MAC.Size])
			if !bytes.Equal(mac, sig[2:]) {
				t.Errorf("key %d: MAC is not over SI..payload", id)
			}
		default:
			pt, err := k.aead.Open(nil, iv, append(append([]byte(nil), b[ps:len(b)-18]...), sig[2:]...), b[2:ps])
			if err != nil || !bytes.Contains(pt, g1) {
				t.Errorf("key %d: GCM with AAD SI..PayloadLength: %v", id, err)
			}
		}
		s, sec, err := OpenRoutable(b, ks, now)
		if err != nil || sec == nil || sec.Key != k || len(s.Payloads) != 1 || !bytes.Equal(s.Payloads[0].APDU, g1) {
			t.Fatalf("key %d: opened %+v %+v, %v", id, s, sec, err)
		}
		// Any altered octet is refused.
		for _, at := range []int{2, 12, ps + 3, len(b) - 1} {
			c := append([]byte(nil), b...)
			c[at] ^= 0x40
			if _, _, err := OpenRoutable(c, ks, now); err == nil {
				t.Errorf("key %d: octet %d altered and accepted", id, at)
			}
		}
		if _, err := DecodeRoutable(b); !errors.Is(err, ErrSecuredSPDU) {
			t.Errorf("key %d without keys: %v", id, err)
		}
	}
	// HMAC after padding; an unknown key.
	b, _ := SealRoutable(spdu, ks.byID(11), 0, 30, nil)
	if binary.BigEndian.Uint16(b[6+14:]) != 30 {
		t.Errorf("TimeOfNextKey = %d", binary.BigEndian.Uint16(b[6+14:]))
	}
	unk := append([]byte(nil), b...)
	binary.BigEndian.PutUint32(unk[6+16:], 99)
	var ek *KeyError
	if _, _, err := OpenRoutable(unk, ks, now); !errors.As(err, &ek) || ek.Event != "unknown-key" {
		t.Errorf("unknown key: %v", err)
	}
	k := ks.byID(11)
	raw, _ := EncodeRoutable(SPDU{SI: SIGOOSE, Version: SessionVersion, KeyID: 11, Payloads: spdu.Payloads})
	raw = append(raw, paddingTag, 2, 0, 0)
	binary.BigEndian.PutUint32(raw[6:], binary.BigEndian.Uint32(raw[6:])+4+12)
	raw = append(append(raw, 0x85, 10), k.sum(nil, raw[2:])...)
	if _, _, err := OpenRoutable(raw, ks, now); err != nil {
		t.Errorf("HMAC after padding: %v", err)
	}
	// A key without a MAC cannot secure a routable SPDU.
	nk, _ := NewSecKey(KeySpec{KeyID: 5, MAC: "none"}, true)
	if _, err := SealRoutable(spdu, nk, 0, -1, nil); err == nil {
		t.Error("MAC-None SPDU sealed")
	}
}

// Keys: the current key of a stream by validity window, the next one
// scheduled, TimeOfCurrentKey and TimeToNextKey counting down, the
// rollover, and the last key kept (with an alarm) after it expired.
//
// Covers: SIG-SEC-714, SIG-SEC-715
func TestKeyRollover(t *testing.T) {
	t1 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)
	t3 := t2.Add(time.Hour)
	ks, err := NewKeyStore(KeyStoreOptions{Keys: []KeySpec{
		{KeyID: 1, APPID: ap(0x3001), MAC: "hmac-sha256-128", Key: hmacKey, ValidFrom: &t1, ValidUntil: &t2},
		{KeyID: 2, APPID: ap(0x3001), MAC: "hmac-sha256-128", Key: hmacKey, ValidFrom: &t2, ValidUntil: &t3},
		{KeyID: 3, APPID: ap(0x3002), MAC: "hmac-sha256-128", Key: hmacKey},
	}}, t1)
	if err != nil {
		t.Fatal(err)
	}
	at := t2.Add(-90 * time.Second)
	cur, next, exp := ks.Current(0x3001, "", at)
	tock, ttnk := ks.AuthFields(cur, next, at)
	if cur.ID != 1 || next.ID != 2 || exp || tock != uint32(t1.Unix()) || ttnk != 90 {
		t.Errorf("before rollover: %v %v %v %d %d", cur.ID, next, exp, tock, ttnk)
	}
	cur, next, _ = ks.Current(0x3001, "", t2)
	tock, ttnk = ks.AuthFields(cur, next, t2)
	if cur.ID != 2 || next != nil || tock != uint32(t2.Unix()) || ttnk != -1 {
		t.Errorf("after rollover: %v %v %d %d", cur.ID, next, tock, ttnk)
	}
	if cur, _, exp := ks.Current(0x3001, "", t3.Add(time.Minute)); cur.ID != 2 || !exp {
		t.Errorf("after the last key expired: %v %v", cur.ID, exp)
	}
	// Both keys verify around the switch (clock skew); key 1 later not.
	if _, st := ks.Lookup(1, 0x3001, "", t2.Add(10*time.Second)); st != KeyOK {
		t.Errorf("key 1 just after the switch: %v", st)
	}
	if _, st := ks.Lookup(1, 0x3001, "", t2.Add(time.Hour)); st != KeyExpired {
		t.Errorf("key 1 an hour later: %v", st)
	}
	if _, st := ks.Lookup(2, 0x3001, "", t3.Add(time.Hour)); st != KeyExpiredAssumed {
		t.Errorf("last key after expiry: %v", st)
	}
	if _, st := ks.Lookup(3, 0x3001, "", t2); st != KeyUnknown {
		t.Errorf("key of another APPID: %v", st)
	}
	// Key settings that are refused.
	for name, c := range map[string]KeySpec{
		"key id 0":       {KeyID: 0, MAC: "hmac-sha256", Key: hmacKey},
		"short HMAC key": {KeyID: 1, MAC: "hmac-sha256", Key: "0011"},
		"GMAC key size":  {KeyID: 1, MAC: "aes-gmac-64", Key: strings.Repeat("00", 24)},
		"GCM with HMAC":  {KeyID: 1, MAC: "hmac-sha256", Encryption: EncAES128GCM, Key: strings.Repeat("00", 32)},
		"GCM key size":   {KeyID: 1, MAC: "aes-gmac-128", Encryption: EncAES256GCM, Key: strings.Repeat("00", 16)},
		"unknown mac":    {KeyID: 1, MAC: "md5", Key: hmacKey},
		"MAC-None":       {KeyID: 1, MAC: "none"},
		"window":         {KeyID: 1, MAC: "hmac-sha256", Key: hmacKey, ValidFrom: &t2, ValidUntil: &t1},
		"bad hex":        {KeyID: 1, MAC: "hmac-sha256", Key: "zz"},
	} {
		if _, err := NewSecKey(c, false); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := NewKeyStore(KeyStoreOptions{Keys: []KeySpec{{KeyID: 1, MAC: "hmac-sha256", Key: hmacKey}, {KeyID: 1, MAC: "hmac-sha256", Key: hmacKey}}}, t1); err == nil {
		t.Error("a key ID given twice was accepted")
	}
}

// The savPdu security field (62351-6 6.2.2.2) with its timestamp.
//
// Covers: SIG-SEC-708
func TestSVSecurityField(t *testing.T) {
	ts := time.Date(2026, 9, 2, 1, 2, 3, 0, time.UTC)
	b := EncodeSV(Frame{Dst: net1, Src: net2, VLAN: -1, APPID: 0x4001, SV: &SV{SecurityT: ts, ASDUs: []ASDU{{SvID: "MU", SmpCnt: 1, ConfRev: 1, SeqData: make([]byte, 16)}}}})
	i := bytes.Index(b, []byte{0xa1, 0x0c, 0xa0, 0x0a, 0x80, 0x08})
	if i < 0 {
		t.Fatalf("no [1] { [0] { [0] timestamp } } in %x", b)
	}
	f, err := Decode(b)
	if err != nil || !f.SV.SecurityT.Equal(ts) {
		t.Fatalf("decoded %+v, %v", f.SV, err)
	}
	// A timestamp directly inside [1] is read too (F-812).
	b2 := append([]byte(nil), b...)
	b2 = append(b2[:i], append([]byte{0xa1, 0x0a}, b2[i+4:]...)...)
	binary.BigEndian.PutUint16(b2[16:], binary.BigEndian.Uint16(b2[16:])-2)
	b2[23] -= 2 // savPdu length (one octet here)
	if f, err := Decode(b2); err != nil || !f.SV.SecurityT.Equal(ts) {
		t.Errorf("inner form: %v, %v", f, err)
	}
}
