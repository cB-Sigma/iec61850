package goose

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

// expNxtPk of 62351-6 6.2.2.3 state 6 for the three sample modes.
//
// Covers: SIG-SEC-723
func TestExpNxtPk(t *testing.T) {
	for _, c := range []struct {
		no, rate, mod int
		f             float64
		want          time.Duration
	}{
		{1, 4000, SmpPerSec, 50, 500 * time.Microsecond},     // (1/4000)*2
		{8, 4800, SmpPerSec, 60, 3333333 * time.Nanosecond},  // (8/4800)*2
		{1, 80, SmpPerPeriod, 50, 500 * time.Microsecond},    // ((1/80)/50)*2
		{2, 256, SmpPerPeriod, 60, 260417 * time.Nanosecond}, // ((2/256)/60)*2
		{1, 2, SecPerSmp, 50, 4 * time.Second},               // 2*1*2
		{1, 0, SmpPerSec, 50, 0},
	} {
		if got := ExpNxtPk(c.no, c.rate, c.mod, c.f); got != c.want {
			t.Errorf("ExpNxtPk(%d, %d, %d, %v) = %v, want %v", c.no, c.rate, c.mod, c.f, got, c.want)
		}
	}
}

// AES-128-CBC and AES-256-CBC on routable SPDUs (Tables 11 and 12): the
// user payloads and the padding element are encrypted under the 16-octet
// IV, PayloadLength stays in clear, and the MAC (HMAC-SHA256 or AES-GMAC
// under the separate macKey, same IV) covers the SPDU from the SI to the
// end of the ciphertext (our reading, F-821).
//
// Covers: SIG-SEC-728
func TestRoutableAESCBC(t *testing.T) {
	g1 := goosePDU(t, 1, false)
	spdu := SPDU{SI: SIGOOSE, Version: SessionVersion, Payloads: []Payload{{Tag: PayloadGOOSE, APPID: 0x3001, APDU: g1}}}
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	encKey := strings.Repeat("5a", 16)
	ks, err := NewKeyStore(KeyStoreOptions{Keys: []KeySpec{
		{KeyID: 21, MAC: "hmac-sha256-128", Encryption: EncAES128CBC, Key: encKey, MACKey: hmacKey},
		{KeyID: 22, MAC: "aes-gmac-128", Encryption: EncAES256CBC, Key: strings.Repeat("6b", 32), MACKey: strings.Repeat("7c", 16)},
	}}, now)
	if err != nil {
		t.Fatal(err)
	}
	iv := hx(t, "f0e0d0c0b0a090807060504030201000")
	for _, id := range []uint32{21, 22} {
		k := ks.byID(id)
		b, err := SealRoutable(spdu, k, 0, -1, iv)
		if err != nil {
			t.Fatal(err)
		}
		ps := 6 + int(b[5]) + 4
		n := int(binary.BigEndian.Uint32(b[ps-4:]))
		if n != 4+2+len(g1) {
			t.Errorf("key %d: PayloadLength %d is not the clear payload length", id, n)
		}
		ctEnd := len(b) - 2 - k.MAC.Size
		ct := b[ps:ctEnd]
		if len(ct)%16 != 0 || len(ct) < n+2 || bytes.Contains(b, g1) {
			t.Fatalf("key %d: ciphertext of %d octets", id, len(ct))
		}
		if id == 21 {
			blk, _ := aes.NewCipher(hx(t, encKey))
			pt := make([]byte, len(ct))
			cipher.NewCBCDecrypter(blk, iv).CryptBlocks(pt, ct)
			pad := pt[n:]
			if pad[0] != paddingTag || int(pad[1]) != len(pad)-2 || !bytes.Contains(pt, g1) {
				t.Errorf("plaintext tail %x", pad)
			}
			if !bytes.Equal(k.sum(iv, b[2:ctEnd]), b[ctEnd+2:]) {
				t.Error("the MAC is not over SI..ciphertext under the macKey")
			}
		}
		s, sec, err := OpenRoutable(b, ks, now)
		if err != nil || sec.Key != k || !bytes.Equal(s.Payloads[0].APDU, g1) {
			t.Fatalf("key %d: %+v, %v", id, s, err)
		}
		c := append([]byte(nil), b...)
		c[ps+1] ^= 1
		var ek *KeyError
		if _, _, err := OpenRoutable(c, ks, now); !errors.As(err, &ek) || ek.Event != "mac-failure" {
			t.Errorf("key %d: altered ciphertext: %v", id, err)
		}
	}
	for name, c := range map[string]KeySpec{
		"CBC without macKey": {KeyID: 1, MAC: "hmac-sha256", Encryption: EncAES128CBC, Key: strings.Repeat("00", 16)},
		"CBC key size":       {KeyID: 1, MAC: "hmac-sha256", Encryption: EncAES256CBC, Key: strings.Repeat("00", 16), MACKey: hmacKey},
		"CBC with MAC-None":  {KeyID: 1, MAC: "none", Encryption: EncAES128CBC, Key: strings.Repeat("00", 16), MACKey: hmacKey},
	} {
		if _, err := NewSecKey(c, true); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Layer 2 never encrypts.
	if _, err := SecureL2(securedTestFrame(t, 1), ks.byID(21), 0, -1, nil); err == nil {
		t.Error("Layer 2 CBC accepted")
	}
}

// A secured SV stream: smpCnt counts and wraps per second, each savPdu
// carries a strictly increasing security timestamp (8-1 time stamp
// resolution), and every frame carries the Layer 2 extension that a
// subscriber verifies; the same stream goes out as secured routable SV.
//
// Covers: SIG-SEC-727
func TestSecuredSVStream(t *testing.T) {
	ks := testKeys(t)
	s := &SVStream{Dst: net1, Src: net2, VLAN: 0, Priority: 4, APPID: 0x4001, SvID: "MU01", ConfRev: 1, SmpRate: 80, NominalHz: 50,
		SmpSynch: 2, Keys: ks, Secure: true}
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	var last time.Time
	for i := range 4002 {
		b, err := s.Frame(make([]Sample, 8), now) // the same clock reading every time
		if err != nil {
			t.Fatal(err)
		}
		f, err := Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		a := f.SV.ASDUs[0]
		if int(a.SmpCnt) != i%4000 || a.SmpRate != 80 {
			t.Fatalf("frame %d smpCnt %d smpRate %d", i, a.SmpCnt, a.SmpRate)
		}
		if !f.SV.SecurityT.After(last) {
			t.Fatalf("frame %d security timestamp %v not after %v", i, f.SV.SecurityT, last)
		}
		last = f.SV.SecurityT
		if _, _, fail := ks.Check(true, f, "", now); fail != nil {
			t.Fatalf("frame %d: %v", i, fail)
		}
	}
	r, err := s.Routable(make([]Sample, 8), now, 5)
	if err != nil {
		t.Fatal(err)
	}
	sp, sec, err := OpenRoutable(r, ks, now)
	if err != nil || sp.SI != SISV || sec == nil || sec.Key.ID != 7 {
		t.Fatalf("routable SV %+v %+v, %v", sp, sec, err)
	}
	fs, err := sp.Frames()
	if err != nil || fs[0].SV.SecurityT.IsZero() {
		t.Errorf("routable SV frames %+v, %v", fs, err)
	}
}
