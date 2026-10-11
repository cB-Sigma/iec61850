package mms

import (
	"fmt"
	"net"
	"slices"
	"time"
)

// TLSPort is the TCP port of MMS over TLS (IEC 62351-4 6.3.2); plain MMS
// uses 102 (6.3.3).
const TLSPort = "3782"

// MinSessionLifetime is the shortest session resumption lifetime IEC
// 62351-4 6.2.3 allows (resumption supported for at least two hours).
const MinSessionLifetime = 2 * time.Hour

// MandatorySuites12 are the TLS 1.2 cipher suites IEC 62351-4 Table 10
// makes mandatory for native mode that the IEC 62351-3 profile offers by
// default; a narrowed cipherSuites list keeps them (6.3.4.1).
var MandatorySuites12 = []string{"TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}

// StaticDHSuite is the fourth mandatory native-mode suite (static
// Diffie-Hellman with DH certificates, Table 10). It is offered and
// accepted when configured: staticDH on a client, staticDHCert and
// staticDHKey on a server (which turn staticDH on); a narrowed
// cipherSuites list with staticDH keeps it (F-832).
const StaticDHSuite = "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"

// TLSParams are the parts of an IEC 62351-3 TLS profile configuration
// IEC 62351-4 6.2 constrains for MMS, as CheckTLSParams reads them.
type TLSParams struct {
	// SessionLifetime is the configured session resumption lifetime (0:
	// the profile's default).
	SessionLifetime time.Duration
	// Renegotiation is the renegotiation (key update) interval in effect,
	// CRLRefresh the CRL refresh period in effect (the profile's defaults
	// filled in).
	Renegotiation, CRLRefresh time.Duration
	// Versions are the configured TLS versions ("1.2", "1.3"; empty: the
	// profile's default, which includes 1.2).
	Versions []string
	// CipherSuites is a narrowed TLS 1.2 suite list (empty: the profile's
	// default).
	CipherSuites []string
	// StaticDH offers or accepts StaticDHSuite; HasStaticDHCert and
	// HasStaticDHKey say whether a server's static DH certificate and key
	// are configured.
	StaticDH                        bool
	HasStaticDHCert, HasStaticDHKey bool
}

// CheckTLSParams applies what IEC 62351-4 6.2 adds to the IEC 62351-3
// profile for MMS: sessions resumable for at least two hours (6.2.3),
// renegotiation at least every half CRL refresh period (6.2.4; the
// profile keeps the 10 minute lower bound) and the mandatory TLS 1.2
// suites in a narrowed list (6.3.4). A server configured with a static DH
// certificate and key gets StaticDH turned on (p is changed).
func CheckTLSParams(p *TLSParams) error {
	if l := p.SessionLifetime; l != 0 && l < MinSessionLifetime {
		return fmt.Errorf("sessionLifetime %s is below the 2h IEC 62351-4 6.2.3 asks for", l)
	}
	if p.Renegotiation > p.CRLRefresh/2 {
		return fmt.Errorf("renegotiationInterval %s is above half the CRL refresh period %s (IEC 62351-4 6.2.4)", p.Renegotiation, p.CRLRefresh)
	}
	if p.HasStaticDHCert || p.HasStaticDHKey {
		if !p.HasStaticDHCert || !p.HasStaticDHKey {
			return fmt.Errorf("staticDHCert and staticDHKey go together (IEC 62351-4 Table 10, %s)", StaticDHSuite)
		}
		p.StaticDH = true
	}
	tls12 := len(p.Versions) == 0 || slices.Contains(p.Versions, "1.2")
	if p.StaticDH && !tls12 {
		return fmt.Errorf("staticDH needs TLS 1.2 (%s)", StaticDHSuite)
	}
	if len(p.CipherSuites) > 0 && tls12 {
		mandatory := MandatorySuites12
		if p.StaticDH {
			mandatory = append(slices.Clone(mandatory), StaticDHSuite)
		}
		for _, m := range mandatory {
			if !slices.Contains(p.CipherSuites, m) {
				return fmt.Errorf("cipherSuites must keep %s (mandatory in IEC 62351-4 Table 10)", m)
			}
		}
	}
	return nil
}

// DefaultAddr adds the default port to an address without one: 3782 with
// TLS, 102 without.
func DefaultAddr(addr string, withTLS bool) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	if withTLS {
		return net.JoinHostPort(addr, TLSPort)
	}
	return net.JoinHostPort(addr, "102")
}
