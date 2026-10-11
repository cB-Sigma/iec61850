// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package testpki makes throw-away certificate authorities and
// certificates, and records security events, for the module's tests.
package testpki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/iotsec"
)

// CA is a test certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	PEM  string

	mu     sync.Mutex
	serial int64
}

// NewCA makes an ECDSA P-256 root valid from an hour ago for two days.
func NewCA(name string) (*CA, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: c, Key: k, PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), serial: 1}, nil
}

// MustCA is NewCA that panics on error.
func MustCA(name string) *CA {
	ca, err := NewCA(name)
	if err != nil {
		panic(err)
	}
	return ca
}

// Pool is a pool holding the CA's certificate.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// Leaf describes a certificate to issue.
type Leaf struct {
	Name   string // common name and DNS name
	Server bool   // server (ServerAuth, DNS name and 127.0.0.1) or client (ClientAuth)
	// RSABits makes an RSA key of that size; 0 makes an ECDSA P-256 key.
	RSABits int
	// NotBefore and NotAfter default to an hour ago and a day ahead.
	NotBefore, NotAfter time.Time
	// ExtraNames are added DNS names (to make a certificate large).
	ExtraNames []string
}

// Issued is an issued certificate with its key.
type Issued struct {
	Cert    *x509.Certificate
	Key     crypto.Signer
	CertPEM string
	KeyPEM  string
}

// Issue signs a certificate for l.
func (ca *CA) Issue(l Leaf) (*Issued, error) {
	var pub crypto.PublicKey
	var key crypto.Signer
	var keyPEM []byte
	if l.RSABits > 0 {
		k, err := rsa.GenerateKey(rand.Reader, l.RSABits)
		if err != nil {
			return nil, err
		}
		pub, key = &k.PublicKey, k
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		pub, key = &k.PublicKey, k
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	}
	now := time.Now()
	nb, na := l.NotBefore, l.NotAfter
	if nb.IsZero() {
		nb = now.Add(-time.Hour)
	}
	if na.IsZero() {
		na = now.Add(24 * time.Hour)
	}
	ca.mu.Lock()
	ca.serial++
	serial := ca.serial
	ca.mu.Unlock()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: l.Name}, NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, DNSNames: append([]string{l.Name}, l.ExtraNames...)}
	if l.Server {
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Issued{Cert: c, Key: key, CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), KeyPEM: string(keyPEM)}, nil
}

// MustIssue is Issue that panics on error.
func (ca *CA) MustIssue(l Leaf) *Issued {
	i, err := ca.Issue(l)
	if err != nil {
		panic(err)
	}
	return i
}

// Recorder keeps security events in memory (an iotsec.Auditor).
type Recorder struct {
	mu     sync.Mutex
	events []iotsec.SecurityEvent
}

// RecordSecurity keeps e.
func (r *Recorder) RecordSecurity(_ context.Context, e iotsec.SecurityEvent) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

// Events returns the recorded events.
func (r *Recorder) Events() []iotsec.SecurityEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]iotsec.SecurityEvent(nil), r.events...)
}

// Find returns the events with mnemonic (any case), optionally only those
// whose subject contains subject.
func (r *Recorder) Find(mnemonic, subject string) []iotsec.SecurityEvent {
	var out []iotsec.SecurityEvent
	for _, e := range r.Events() {
		if e.Event == strings.ToLower(mnemonic) && strings.Contains(e.Subject, subject) {
			out = append(out, e)
		}
	}
	return out
}

// Wait waits up to d for an event with mnemonic and subject.
func (r *Recorder) Wait(mnemonic, subject string, d time.Duration) (iotsec.SecurityEvent, error) {
	end := time.Now().Add(d)
	for {
		if f := r.Find(mnemonic, subject); len(f) > 0 {
			return f[0], nil
		}
		if time.Now().After(end) {
			var n []string
			for _, e := range r.Events() {
				n = append(n, e.Event+"("+e.Subject+")")
			}
			return iotsec.SecurityEvent{}, fmt.Errorf("no %s event for %q in %s; have %s", mnemonic, subject, d, strings.Join(n, " "))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
