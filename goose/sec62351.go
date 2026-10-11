package goose

// IEC 62351-6:2020 security for GOOSE and sampled values: the Layer 2
// extension (clause 8.2: the security extension length in Reserved 1, a
// CRC of the header in Reserved 2, the BER Extension with the
// AuthenticationValue and the mAC after the APDU), the MAC functions and
// keys, and the checks a subscriber makes (6.2.1.2, 6.2.2.3.1).
//
// Keys come from the configuration (static keys per APPID and data set,
// with key IDs and validity windows) and from a key distribution centre
// (the GDOI GROUPKEY-PULL of IEC 62351-9, 8.2.2.4.1, 9.2.3), which the
// application runs and hands over with KeyStore.Deliver.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/iec61850/mms"
)

// MACAlg is a MAC function of 8.2.2.2 and Tables 9 to 12 with the length
// of the value sent (RFC 2104 truncation to the leftmost octets; for
// AES-GMAC the leftmost octets of the tag, NIST SP 800-38D 5.2.1.2).
type MACAlg struct {
	Name string
	HMAC bool // HMAC-SHA256; otherwise AES-GMAC (or MAC-None when Size is 0)
	Size int
}

// macAlgs are the MAC functions a key may use. AES-GMAC runs with an
// AES-128 or AES-256 key, chosen by the key's length (F-806).
var macAlgs = map[string]MACAlg{
	"none":            {Name: "none"},
	"hmac-sha256-80":  {Name: "hmac-sha256-80", HMAC: true, Size: 10},
	"hmac-sha256-128": {Name: "hmac-sha256-128", HMAC: true, Size: 16},
	"hmac-sha256":     {Name: "hmac-sha256", HMAC: true, Size: 32},
	"hmac-sha256-256": {Name: "hmac-sha256", HMAC: true, Size: 32},
	"aes-gmac-64":     {Name: "aes-gmac-64", Size: 8},
	"aes-gmac-128":    {Name: "aes-gmac-128", Size: 16},
}

// Confidentiality algorithms (Tables 11 and 12; routable only, 8.2.2.2).
const (
	EncAES128GCM = "aes-128-gcm"
	EncAES256GCM = "aes-256-gcm"
	EncAES128CBC = "aes-128-cbc"
	EncAES256CBC = "aes-256-cbc"
)

const (
	authVersion = 1  // 8.2.2.3.2
	ivSize      = 16 // 8.2.2.3.5
	minMACSize  = 8  // 8.2.2.2: the output is at least eight octets
	gcmTagSize  = 16
	// keyClockSkew is how far a publisher's clock may be ahead or behind
	// ours when it starts or stops using a key.
	keyClockSkew = 30 * time.Second
	// maxExtension is the 12-bit security extension length (Figure 5).
	maxExtension = 0x0fff
)

// KeySpec is a static group key: a key ID, the streams it protects
// (APPID and data set; any when empty), its algorithms (MAC: none,
// hmac-sha256-80, hmac-sha256-128, hmac-sha256, aes-gmac-64, aes-gmac-128;
// Encryption: none, aes-128-gcm, aes-256-gcm, aes-128-cbc, aes-256-cbc),
// the key itself (hex, or "file:<path>" of a mounted secret) and its
// validity window.
type KeySpec struct {
	KeyID      uint32
	APPID      APPID
	DataSet    string
	MAC        string
	Encryption string
	Key        string
	// MACKey is the MAC key of an AES-CBC key (Key then being the
	// encryption key); other algorithms use Key for both.
	MACKey     string
	ValidFrom  *time.Time
	ValidUntil *time.Time
}

// KeyStoreOptions configure a KeyStore.
type KeyStoreOptions struct {
	Keys []KeySpec
	// MaxTimeDeviation bounds how far the t of a GOOSE message with a new
	// stNum may be from our clock (6.2.1.3; the deviation is a local
	// choice). 0 turns the check off.
	MaxTimeDeviation time.Duration
	// AllowMACNone accepts keys with MAC-None, which 8.2.2.2 allows for
	// testing only.
	AllowMACNone bool
	// ExpiredGrace is how long a delivered key stays usable after it
	// expired when no new one arrived (IEC 62351-9 8.7.2; 0: no limit).
	ExpiredGrace time.Duration
}

// SecKey is a configured key ready for use.
type SecKey struct {
	ID          uint32
	APPID       APPID
	DataSet     string
	MAC         MACAlg
	Encryption  string
	From, Until time.Time
	// Delivered marks a key from the GDOI key server (not configuration);
	// it is accepted for ExpiredGrace after it expires (IEC 62351-9 8.7.2).
	Delivered bool
	// Held is a delivered key whose key delivery assurance is below the
	// stream's kdaThreshold: a publisher does not switch to it yet.
	Held   bool
	KDA    int // delivered SA_KDA
	secret []byte
	aead   cipher.AEAD  // AES-GCM with a 16-octet IV (GMAC and GCM)
	cbc    cipher.Block // AES-CBC encryption (Key; the MAC uses macKey)
}

// SecretBytes reads key octets given as hex (colons allowed), inline or
// as "file:<path>" of a mounted secret.
func SecretBytes(v string) ([]byte, error) {
	if p, ok := strings.CutPrefix(v, "file:"); ok {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		v = string(b)
	}
	return hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(v), ":", ""))
}

// NewSecKey checks a key specification and makes the key ready for use;
// allowNone accepts MAC-None (testing only, IEC 62351-6 8.2.2.2).
func NewSecKey(c KeySpec, allowNone bool) (*SecKey, error) {
	if c.KeyID == 0 {
		return nil, errors.New("keyId 0 means unsecured and cannot name a key")
	}
	alg, ok := macAlgs[strings.ToLower(c.MAC)]
	if !ok {
		return nil, fmt.Errorf("mac %q is not one of none, hmac-sha256-80, hmac-sha256-128, hmac-sha256, aes-gmac-64, aes-gmac-128", c.MAC)
	}
	if alg.Size == 0 && !allowNone {
		return nil, errors.New("mac none is for testing only (set allowMacNone)")
	}
	k := &SecKey{ID: c.KeyID, APPID: c.APPID, DataSet: c.DataSet, MAC: alg, Encryption: strings.ToLower(c.Encryption)}
	if c.ValidFrom != nil {
		k.From = *c.ValidFrom
	}
	if c.ValidUntil != nil {
		k.Until = *c.ValidUntil
	}
	if !k.From.IsZero() && !k.Until.IsZero() && !k.Until.After(k.From) {
		return nil, errors.New("validUntil is not after validFrom")
	}
	var err error
	if k.secret, err = SecretBytes(c.Key); err != nil {
		return nil, errors.New("key: hex octets, inline or in a file:")
	}
	switch k.Encryption {
	case "", "none":
		k.Encryption = ""
	case EncAES128CBC, EncAES256CBC:
		// Encrypt, then MAC under a separate key (F-821).
		if alg.Size == 0 {
			return nil, fmt.Errorf("encryption %s needs a MAC", k.Encryption)
		}
		if want := map[string]int{EncAES128CBC: 16, EncAES256CBC: 32}[k.Encryption]; len(k.secret) != want {
			return nil, fmt.Errorf("encryption %s needs a %d-octet key", k.Encryption, want)
		}
		if k.cbc, err = aes.NewCipher(k.secret); err != nil {
			return nil, err
		}
		if c.MACKey == "" {
			return nil, fmt.Errorf("encryption %s needs macKey", k.Encryption)
		}
		if k.secret, err = SecretBytes(c.MACKey); err != nil {
			return nil, errors.New("macKey: hex octets, inline or in a file:")
		}
	case EncAES128GCM, EncAES256GCM:
		// With AES-GCM the MAC is the GCM tag (Tables 11 and 12, c1 c2).
		if alg.HMAC || alg.Size != gcmTagSize {
			return nil, fmt.Errorf("encryption %s needs mac aes-gmac-128 (its tag)", k.Encryption)
		}
		if want := map[string]int{EncAES128GCM: 16, EncAES256GCM: 32}[k.Encryption]; len(k.secret) != want {
			return nil, fmt.Errorf("encryption %s needs a %d-octet key", k.Encryption, want)
		}
	default:
		return nil, fmt.Errorf("encryption %q is not none, aes-128-gcm, aes-256-gcm, aes-128-cbc or aes-256-cbc", c.Encryption)
	}
	switch {
	case alg.Size == 0:
	case alg.HMAC:
		if len(k.secret) < sha256.Size {
			return nil, errors.New("an HMAC-SHA256 key needs at least 32 octets (RFC 2104 section 3)")
		}
	default:
		if len(k.secret) != 16 && len(k.secret) != 32 {
			return nil, errors.New("an AES-GMAC key is 16 (AES-128) or 32 (AES-256) octets")
		}
		blk, err := aes.NewCipher(k.secret)
		if err != nil {
			return nil, err
		}
		if k.aead, err = cipher.NewGCMWithNonceSize(blk, ivSize); err != nil {
			return nil, err
		}
	}
	return k, nil
}

// needsIV reports whether the key's algorithm takes the 16-octet
// initialisation vector (8.2.2.3.5).
func (k *SecKey) needsIV() bool { return k.aead != nil || k.cbc != nil }

// gcm reports whether the key encrypts with AES-GCM (the tag is the MAC).
func (k *SecKey) gcm() bool { return k.Encryption == EncAES128GCM || k.Encryption == EncAES256GCM }

// sum is the MAC of data (IV for AES-GMAC), truncated to the algorithm's
// size.
func (k *SecKey) sum(iv, data []byte) []byte {
	switch {
	case k.MAC.Size == 0:
		return nil
	case k.MAC.HMAC:
		m := hmac.New(sha256.New, k.secret)
		m.Write(data)
		return m.Sum(nil)[:k.MAC.Size]
	default:
		return k.aead.Seal(nil, iv, nil, data)[:k.MAC.Size]
	}
}

// Sample modes of IEC 61850-7-2 (smpMod).
const (
	SmpPerPeriod = 0
	SmpPerSec    = 1
	SecPerSmp    = 2
)

// ExpNxtPk is the time within which the next SV packet is expected
// (62351-6 6.2.2.3 state 6), in seconds as the formulas give it; 0 when
// smpRate is not known.
func ExpNxtPk(noASDU, smpRate, smpMod int, nominalHz float64) time.Duration {
	if smpRate <= 0 || noASDU <= 0 {
		return 0
	}
	var sec float64
	switch smpMod {
	case SecPerSmp:
		sec = float64(smpRate) * float64(noASDU) * 2
	case SmpPerSec:
		sec = float64(noASDU) / float64(smpRate) * 2
	default:
		if nominalHz <= 0 {
			return 0
		}
		sec = float64(noASDU) / float64(smpRate) / nominalHz * 2
	}
	return time.Duration(math.Round(sec * float64(time.Second)))
}

func (k *SecKey) verify(iv, data, mac []byte) bool {
	if len(mac) != k.MAC.Size || (k.needsIV() && len(iv) != ivSize) {
		return false
	}
	return subtle.ConstantTimeCompare(k.sum(iv, data), mac) == 1
}

// scoped reports whether the key protects the stream.
func (k *SecKey) Scoped(appid uint16, dataSet string) bool {
	return k.APPID.matches(appid) && (k.DataSet == "" || dataSet == "" || k.DataSet == dataSet)
}

// KeyStore holds the configured keys and those a GDOI key server
// delivered. It is safe for concurrent use: deliveries replace the key
// list, readers take a snapshot.
type KeyStore struct {
	mu    sync.RWMutex
	keys  []*SecKey
	start time.Time
	// expiredGrace is how long a delivered key stays usable after it
	// expired when no new one arrived (IEC 62351-9 8.7.2; 0: no limit).
	expiredGrace time.Duration
	// Settings
	maxDeviation time.Duration
}

// NewKeyStore checks and loads the keys; start stands for the time a key
// without validFrom was first used (TimeOfCurrentKey).
func NewKeyStore(s KeyStoreOptions, start time.Time) (*KeyStore, error) {
	ks := &KeyStore{start: start, maxDeviation: s.MaxTimeDeviation, expiredGrace: s.ExpiredGrace}
	ids := map[uint32]bool{}
	for i, c := range s.Keys {
		k, err := NewSecKey(c, s.AllowMACNone)
		if err != nil {
			return nil, fmt.Errorf("key %d (%d): %w", i+1, c.KeyID, err)
		}
		if ids[k.ID] {
			return nil, fmt.Errorf("keyId %d is given twice", k.ID)
		}
		ids[k.ID] = true
		ks.keys = append(ks.keys, k)
	}
	return ks, nil
}

// Current is the key a publisher of the stream uses now and the next one
// scheduled. When every key of the stream has expired the last one is
// used and expired is set (6.2.1.1 state 3 keeps expired keys in use when
// no new one arrived).
func (s *KeyStore) Current(appid uint16, dataSet string, now time.Time) (cur, next *SecKey, expired bool) {
	cur, next, expired = s.current(appid, dataSet, now, false)
	if cur == nil || expired {
		// Only keys held back for key delivery assurance: use them rather
		// than none or an expired one.
		if c, n, e := s.current(appid, dataSet, now, true); c != nil && !e {
			return c, n, e
		}
	}
	return cur, next, expired
}

func (s *KeyStore) current(appid uint16, dataSet string, now time.Time, held bool) (cur, next *SecKey, expired bool) {
	var last *SecKey
	for _, k := range s.list() {
		if !k.Scoped(appid, dataSet) || (k.Held && !held) {
			continue
		}
		switch {
		case !k.From.IsZero() && now.Before(k.From):
			if next == nil || k.From.Before(next.From) {
				next = k
			}
		case !k.Until.IsZero() && !now.Before(k.Until):
			if last == nil || k.Until.After(last.Until) {
				last = k
			}
		default:
			// The latest activated; of two activated together, the one
			// that lasts longer (keys delivered by one pull or push).
			if cur == nil || k.From.After(cur.From) || (k.From.Equal(cur.From) && laterUntil(k, cur)) {
				cur = k
			}
		}
	}
	if cur == nil && last != nil {
		return last, next, true
	}
	return cur, next, false
}

func laterUntil(a, b *SecKey) bool {
	if a.Until.IsZero() {
		return !b.Until.IsZero()
	}
	return !b.Until.IsZero() && a.Until.After(b.Until)
}

// heldDue is a key held back for key delivery assurance that would be
// the current key by its time (IEC 62351-9 8.5.10.3).
func (s *KeyStore) HeldDue(appid uint16, dataSet string, now time.Time) *SecKey {
	for _, k := range s.list() {
		if k.Held && k.Scoped(appid, dataSet) && !now.Before(k.From) && (k.Until.IsZero() || now.Before(k.Until)) {
			return k
		}
	}
	return nil
}

// KeyState is the outcome of looking up a received key ID.
// KeyState is the state of the key a message names.
type KeyState int

const (
	KeyOK KeyState = iota
	KeyUnknown
	KeyNotYet
	KeyExpired
	KeyExpiredAssumed // expired, but the last one delivered (6.2.1.1 state 3)
)

// Keys is a snapshot of the keys.
func (s *KeyStore) Keys() []*SecKey { return s.list() }

// ExpiredGrace is how long a delivered key stays usable after it expired.
func (s *KeyStore) ExpiredGrace() time.Duration { return s.expiredGrace }

// MaxDeviation is the configured bound on a new state's time (0: off).
func (s *KeyStore) MaxDeviation() time.Duration { return s.maxDeviation }

// list is a snapshot of the keys.
func (s *KeyStore) list() []*SecKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keys
}

// Deliver installs the keys a GDOI key server delivered for one stream
// (APPID and data set): a pull or push carries the whole current set, so
// earlier delivered keys of the stream not in it are withdrawn, except
// when keys is empty.
func (s *KeyStore) Deliver(keys []*SecKey, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*SecKey
	for _, old := range s.keys {
		drop := false
		for _, k := range keys {
			if old.Delivered && old.APPID == k.APPID && old.DataSet == k.DataSet {
				drop = true
			}
		}
		if !drop {
			out = append(out, old)
		}
	}
	s.keys = append(out, keys...)
}

// Withdraw removes delivered keys by ID (a GROUPKEY-PUSH Delete).
func (s *KeyStore) Withdraw(ids []uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*SecKey
	for _, k := range s.keys {
		keep := true
		for _, id := range ids {
			if k.Delivered && k.ID == id {
				keep = false
			}
		}
		if keep {
			out = append(out, k)
		}
	}
	s.keys = out
}

// Lookup finds the key a received message names.
func (s *KeyStore) Lookup(id uint32, appid uint16, dataSet string, now time.Time) (*SecKey, KeyState) {
	for _, k := range s.list() {
		if k.ID == id && k.Scoped(appid, dataSet) {
			return k, s.state(k, now)
		}
	}
	return nil, KeyUnknown
}

// authFields are TimeOfCurrentKey (seconds since 1970, unsigned 32 bits,
// 8.2.2.3.3) and TimeToNextKey (seconds until the next key is used, -1
// when none is scheduled, 8.2.2.3.4).
func (s *KeyStore) AuthFields(cur, next *SecKey, now time.Time) (uint32, int64) {
	from := cur.From
	if from.IsZero() {
		from = s.start
	}
	ttnk := int64(-1)
	if next != nil {
		ttnk = int64((next.From.Sub(now) + time.Second - 1) / time.Second)
		if ttnk < 1 {
			ttnk = 1
		}
	}
	return uint32(from.Unix()), ttnk
}

// ---- Layer 2 extension (8.2) ------------------------------------------------

// AuthValue is the AuthenticationValue of 8.2.2.3.1.
type AuthValue struct {
	Version          int64
	TimeOfCurrentKey uint32
	TimeToNextKey    int64
	IV               []byte
	KeyID            uint32
}

// FrameSec is what a frame carries of IEC 62351-6: the Layer 2
// extension, or the outcome of a secured routable SPDU.
type FrameSec struct {
	// ExtLen is the security extension length of Reserved 1.
	ExtLen int
	// CRCOK: Reserved 2 holds the CRC of octets 1 to 8.
	CRCOK bool
	Auth  *AuthValue
	MAC   []byte
	// Malformed says why the extension could not be read.
	Malformed string
	// Routable is set for a routable SPDU already verified (or decrypted)
	// with Key.
	Routable bool
	Key      *SecKey
	KeyState KeyState
	signed   []byte // the calculated mAC domain (Figure 6)
}

// crc16 is the 16-bit FCS of ISO/IEC 13239 (reflected polynomial 0x8408,
// initial value 0xFFFF, ones' complement of the result).
func crc16(b []byte) uint16 {
	c := uint16(0xffff)
	for _, x := range b {
		c ^= uint16(x)
		for i := 0; i < 8; i++ {
			if c&1 != 0 {
				c = c>>1 ^ 0x8408
			} else {
				c >>= 1
			}
		}
	}
	return ^c
}

func berInt(tag byte, v int64) []byte { return mms.T(tag, mms.IntBytes(v)) }

// intOf reads a BER INTEGER (two's complement, at most 8 octets).
func intOf(b []byte) (int64, error) {
	if len(b) == 0 || len(b) > 8 {
		return 0, errors.New("an INTEGER of bad length")
	}
	v := int64(int8(b[0]))
	for _, c := range b[1:] {
		v = v<<8 | int64(c)
	}
	return v, nil
}

func encodeAuth(a AuthValue) []byte {
	parts := [][]byte{berInt(0x80, a.Version), berInt(0x81, int64(a.TimeOfCurrentKey)), berInt(0x82, a.TimeToNextKey)}
	if len(a.IV) > 0 {
		parts = append(parts, mms.T(0x83, a.IV))
	}
	parts = append(parts, berInt(0x84, int64(a.KeyID)))
	return mms.T(0xa4, parts...)
}

func decodeAuth(e mms.Elem) (*AuthValue, error) {
	kids, err := e.Children()
	if err != nil {
		return nil, err
	}
	a := &AuthValue{}
	seen := map[int]bool{}
	for _, k := range kids {
		if k.Tag&0xc0 != 0x80 {
			continue
		}
		seen[k.Num] = true
		var v int64
		switch k.Num {
		case 0, 1, 2, 4:
			if v, err = intOf(k.Val); err != nil {
				return nil, err
			}
		}
		switch k.Num {
		case 0:
			a.Version = v
		case 1:
			if v < 0 || v > 0xffffffff {
				return nil, errors.New("timeOfCurrentKey outside 0..4294967295")
			}
			a.TimeOfCurrentKey = uint32(v)
		case 2:
			a.TimeToNextKey = v
		case 3:
			a.IV = append([]byte(nil), k.Val...)
		case 4:
			if v < 0 || v > 0xffffffff {
				return nil, errors.New("keyID is not a four-octet value")
			}
			a.KeyID = uint32(v)
		}
	}
	for _, n := range []int{0, 1, 2, 4} {
		if !seen[n] {
			return nil, fmt.Errorf("AuthenticationValue lacks component [%d]", n)
		}
	}
	return a, nil
}

// parseExtension reads the extension octets of a Layer 2 frame; header is
// octets 1 to m+10 (Ethertype to the end of the APDU).
func parseExtension(header, ext []byte) *FrameSec {
	s := &FrameSec{ExtLen: len(ext)}
	e, rest, err := mms.Parse(ext)
	if err != nil || len(rest) != 0 || e.Tag != 0xa0 {
		s.Malformed = "the extension is not one [0] SEQUENCE"
		return s
	}
	body := ext[len(ext)-len(e.Val):]
	signed := append([]byte(nil), header...)
	signed = append(signed, ext[:len(ext)-len(body)]...)
	for len(body) > 0 {
		k, r, err := mms.Parse(body)
		if err != nil {
			s.Malformed = "the extension does not decode"
			return s
		}
		raw := body[:len(body)-len(r)]
		switch k.Tag {
		case 0xa1:
			if len(k.Val) == 0 {
				s.Malformed = "an empty Reserved SEQUENCE (8.2.2.1)"
				return s
			}
		case 0xa4:
			if s.Auth, err = decodeAuth(k); err != nil {
				s.Malformed = "AuthenticationValue: " + err.Error()
				return s
			}
		case 0x85:
			s.MAC = append([]byte{}, k.Val...)
			raw = nil // the mAC is outside its own domain (8.2.2.2)
		}
		signed = append(signed, raw...)
		body = r
	}
	if s.Auth != nil && s.MAC == nil {
		s.Malformed = "an AuthenticationValue without a mAC (8.2.2.1)"
	}
	s.signed = signed
	return s
}

// etherTypeOffset finds the GOOSE/SV ethertype in an Ethernet frame.
func etherTypeOffset(eth []byte) (int, error) {
	i := 12
	for i+2 <= len(eth) {
		switch binary.BigEndian.Uint16(eth[i:]) {
		case etherTypeVLAN:
			i += 4
		case etherTypeHSR:
			i += 6
		case EtherTypeGOOSE, EtherTypeSV:
			if len(eth) < i+10 {
				return 0, errors.New("a truncated GOOSE/SV header")
			}
			return i, nil
		default:
			return 0, ErrNotGOOSEorSV
		}
	}
	return 0, errors.New("a truncated Ethernet header")
}

// SecureL2 adds the IEC 62351-6 extension to an unsecured GOOSE or SV
// frame: the AuthenticationValue and the mAC after the APDU, the
// extension length in Reserved 1 (S bit kept) and the CRC of octets 1 to
// 8 in Reserved 2. iv is used by AES-GMAC (16 octets; drawn when nil).
func SecureL2(eth []byte, k *SecKey, tock uint32, ttnk int64, iv []byte) ([]byte, error) {
	if k.Encryption != "" {
		return nil, errors.New("encryption of Layer 2 GOOSE/SV is out of scope of IEC 62351-6 (8.2.2.2)")
	}
	i, err := etherTypeOffset(eth)
	if err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(eth[i+4:]))
	end := i + 2 + length
	if length < 8 || end > len(eth) {
		return nil, errors.New("the length field does not fit the frame")
	}
	if k.needsIV() && iv == nil {
		iv = make([]byte, ivSize)
		if _, err := rand.Read(iv); err != nil {
			return nil, err
		}
	}
	if !k.needsIV() {
		iv = nil
	}
	auth := encodeAuth(AuthValue{Version: authVersion, TimeOfCurrentKey: tock, TimeToNextKey: ttnk, IV: iv, KeyID: k.ID})
	macTLV := 2 + k.MAC.Size
	ext := mms.T(0xa0, auth, make([]byte, macTLV))
	ext = ext[:len(ext)-macTLV]
	s := len(ext) + macTLV
	if s > maxExtension {
		return nil, errors.New("the security extension is longer than 4095 octets")
	}
	if 8+(length-8)+s > 1500 {
		return nil, fmt.Errorf("the secured frame needs %d octets after the ethertype, more than Ethernet carries", length+s)
	}
	out := append([]byte(nil), eth[:end]...)
	r1 := binary.BigEndian.Uint16(out[i+6:])&0x8000 | uint16(s)
	binary.BigEndian.PutUint16(out[i+6:], r1)
	binary.BigEndian.PutUint16(out[i+8:], crc16(out[i:i+8]))
	signed := append(append([]byte(nil), out[i:]...), ext...)
	mac := k.sum(iv, signed)
	out = append(out, ext...)
	out = append(out, 0x85, byte(len(mac)))
	return append(out, mac...), nil
}

// ---- subscriber checks (6.2.1.2, 6.2.2.3.1) ----------------------------------

// SecFailure is a failed security check: the event name for the security
// log and the reason for status.
// SecFailure is a failed security check of a received message: the
// event name (unknown-key, mac-failure, decrypt-failure, ...) and why.
type SecFailure struct{ Event, Reason string }

// Check runs the security checks for a subscription that expects (or
// not) the AuthenticationValue. It returns the key used when the message
// was verified.
func (s *KeyStore) Check(expect bool, f *Frame, dataSet string, now time.Time) (*SecKey, KeyState, *SecFailure) {
	sec := f.Sec
	present := sec != nil && (sec.Routable || sec.Auth != nil || sec.Malformed != "")
	if !expect {
		// No AuthenticationValue expected: whatever is there is not
		// verified and is no failure (6.2.1.2).
		return nil, KeyOK, nil
	}
	if !present {
		return nil, KeyOK, &SecFailure{"missing-authentication", "no AuthenticationValue on a secured subscription"}
	}
	if s == nil {
		return nil, KeyOK, &SecFailure{"unknown-key", "no keys are configured"}
	}
	if sec.Routable {
		if !sec.Key.Scoped(f.APPID, dataSet) {
			return nil, KeyOK, &SecFailure{"unknown-key", fmt.Sprintf("key %d does not protect this stream", sec.Key.ID)}
		}
		return sec.Key, sec.KeyState, nil
	}
	if sec.Malformed != "" {
		return nil, KeyOK, &SecFailure{"malformed", sec.Malformed}
	}
	if !sec.CRCOK {
		return nil, KeyOK, &SecFailure{"crc-failure", "the Reserved 2 CRC does not match octets 1 to 8"}
	}
	a := sec.Auth
	if a.Version != authVersion {
		return nil, KeyOK, &SecFailure{"malformed", fmt.Sprintf("AuthenticationValue version %d", a.Version)}
	}
	k, st := s.Lookup(a.KeyID, f.APPID, dataSet, now)
	switch st {
	case KeyUnknown:
		return nil, st, &SecFailure{"unknown-key", fmt.Sprintf("key %d is not held", a.KeyID)}
	case KeyNotYet:
		return nil, st, &SecFailure{"key-not-yet-valid", fmt.Sprintf("key %d is not valid yet", a.KeyID)}
	case KeyExpired:
		return nil, st, &SecFailure{"key-expired", fmt.Sprintf("key %d has expired", a.KeyID)}
	}
	if k.Encryption != "" {
		return nil, st, &SecFailure{"malformed", "key " + fmt.Sprint(k.ID) + " encrypts, which Layer 2 does not use"}
	}
	if !k.verify(a.IV, sec.signed, sec.MAC) {
		return nil, st, &SecFailure{"mac-failure", fmt.Sprintf("the mAC does not verify with key %d", a.KeyID)}
	}
	return k, st, nil
}
