// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mms

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/cB-Sigma/iotcrypto/bigmod"
)

// Diffie-Hellman in the 2048-bit MODP group 14 of RFC 3526 (generator 2),
// with constant-time exponentiation, for E2E security's dhGroup 14
// (IEC 62351-4 13.2).

// modp14Prime is the group 14 prime of RFC 3526 section 3.
const modp14Prime = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
	"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
	"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
	"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
	"9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
	"3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"

// modpDH is a key pair in group 14.
type modpDH struct {
	m    *bigmod.Modulus
	size int
	x    []byte
	pub  []byte
}

func newModP14() (*modpDH, error) {
	p, _ := hex.DecodeString(modp14Prime)
	m, err := bigmod.NewModulus(p)
	if err != nil {
		return nil, err
	}
	d := &modpDH{m: m, size: len(p), x: make([]byte, 64)}
	if _, err := rand.Read(d.x); err != nil {
		return nil, err
	}
	g, _ := bigmod.NewNat().SetBytes([]byte{2}, m)
	d.pub = bigmod.NewNat().Exp(g, d.x, m).Bytes(m)
	return d, nil
}

// Public is g^x, as many octets as the prime.
func (d *modpDH) Public() []byte { return d.pub }

// Shared is the peer's value raised to x, as many octets as the prime;
// peer values outside 2..p-2 are refused.
func (d *modpDH) Shared(peer []byte) ([]byte, error) {
	if len(peer) != d.size {
		return nil, fmt.Errorf("KE data is %d octets, the group needs %d", len(peer), d.size)
	}
	y, err := bigmod.NewNat().SetBytes(peer, d.m)
	if err != nil {
		return nil, errors.New("KE value not below the prime")
	}
	pm1 := new(big.Int).Sub(new(big.Int).SetBytes(d.m.Nat().Bytes(d.m)), big.NewInt(1))
	yb := new(big.Int).SetBytes(peer)
	if yb.Cmp(big.NewInt(1)) <= 0 || yb.Cmp(pm1) >= 0 {
		return nil, errors.New("KE value out of range")
	}
	return bigmod.NewNat().Exp(y, d.x, d.m).Bytes(d.m), nil
}
