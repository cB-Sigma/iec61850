// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mms

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/cB-Sigma/iotsec"
)

// StaticIdentity is an AuthIdentity from fixed credentials: this side's
// certificate chain and key, and a peer check that verifies the peer's
// certificate against Roots with crypto/x509 (validity period included) and
// then asks Validator, when set, for revocation and local policy. An
// application with an IEC 62351-3/-9 certificate service implements
// AuthIdentity itself.
type StaticIdentity struct {
	Certificates []*x509.Certificate // leaf first
	Key          crypto.Signer
	Roots        *x509.CertPool
	// InsecureSkipVerify skips the path check to Roots (commissioning
	// only); Validator still runs.
	InsecureSkipVerify bool
	Validator          iotsec.CertValidator
	Now                func() time.Time
}

// NewStaticIdentity reads PEM certificate and key blocks (as
// tls.X509KeyPair does) and the PEM trust anchors (nil: none, so every
// peer fails the path check unless InsecureSkipVerify is set).
func NewStaticIdentity(certPEM, keyPEM, rootsPEM []byte) (*StaticIdentity, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	s := &StaticIdentity{Roots: x509.NewCertPool()}
	for _, der := range pair.Certificate {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		s.Certificates = append(s.Certificates, c)
	}
	k, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("the private key cannot sign")
	}
	s.Key = k
	if len(rootsPEM) > 0 && !s.Roots.AppendCertsFromPEM(rootsPEM) {
		return nil, errors.New("no certificate in the trust anchors")
	}
	return s, nil
}

// Identity returns the certificates and key.
func (s *StaticIdentity) Identity(context.Context) (iotsec.Identity, error) {
	if len(s.Certificates) == 0 || s.Key == nil {
		return iotsec.Identity{}, errors.New("no certificate or key")
	}
	return iotsec.Identity{Certificates: s.Certificates, Key: s.Key}, nil
}

// VerifyPeer verifies chain[0] to Roots (chain[1:] as intermediates), then
// asks Validator.
func (s *StaticIdentity) VerifyPeer(ctx context.Context, chain []*x509.Certificate, peer string) error {
	if len(chain) == 0 {
		return errors.New("no certificate")
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	if !s.InsecureSkipVerify {
		inter := x509.NewCertPool()
		for _, c := range chain[1:] {
			inter.AddCert(c)
		}
		if _, err := chain[0].Verify(x509.VerifyOptions{Roots: s.Roots, Intermediates: inter, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return fmt.Errorf("the certificate of %s does not verify: %w", peer, err)
		}
	} else if now.Before(chain[0].NotBefore) || now.After(chain[0].NotAfter) {
		return fmt.Errorf("the certificate of %s is outside its validity period", peer)
	}
	if s.Validator != nil {
		return s.Validator.ValidateCertificate(ctx, chain[0])
	}
	return nil
}
