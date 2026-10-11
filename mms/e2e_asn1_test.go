package mms

import (
	"encoding/asn1"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850/internal/testpki"
)

// Go types mapped by hand from the E2E-Security module of the IEC
// 62351-4 machine-readable files 2025-11 (IMPLICIT TAGS), independent of e2e.go.
type ccAlgID struct {
	Algorithm asn1.ObjectIdentifier
	Params    asn1.RawValue `asn1:"optional"`
}
type ccDH struct {
	GroupID int
	Pub     []byte
}
type ccToken1 struct {
	SigAlg   ccAlgID
	PKCert   []byte
	CertPath [][]byte       `asn1:"optional"`
	Version  asn1.BitString `asn1:"optional"`
	AssoID   string         `asn1:"utf8"`
	DH       ccDH
	HMAC     ccAlgID
	Time     time.Time `asn1:"generalized"`
	EncrMode asn1.RawValue
	Conf     asn1.BitString
}
type ccTBS struct {
	Token1   ccToken1
	ApplData asn1.RawValue
}
type ccSignature struct {
	Algo ccAlgID
	Sign []byte
}
type ccHandshakeReq struct {
	PP   string `asn1:"utf8"`
	TBS  ccTBS
	Sign ccSignature
}
type ccToken2 struct {
	AssoID  string    `asn1:"utf8"`
	Time    time.Time `asn1:"generalized"`
	Seq     int
	IV      []byte `asn1:"optional,tag:0"`
	Rekey   []byte `asn1:"optional,tag:1"`
	Req     bool   `asn1:"optional,tag:2"`
	Changed bool   `asn1:"optional,tag:3"`
}
type ccTBP struct {
	Token2   ccToken2
	ApplData asn1.RawValue
}
type ccAuthenticator struct {
	Algo ccAlgID
	ICV  []byte
}

// Our HandshakeReq and ClearTransfer SecPDUs decode with types mapped
// from the machine-readable files' ASN.1: pp, ClearToken1 (version v1,
// association ID, DH set, hmacWithSHA256, time, encr-mode, confParams),
// ApplData as [UNIVERSAL 8], the signature; ClearTransfer as [0] of
// DataTransfer with ClearToken2 and the Authenticator (untagged, icv
// mandatory, as the 2025-11 module has it).
// Covers: SIG-IPE-2922
func TestE2EEncodingMatchesCodeComponentASN1(t *testing.T) {
	raw, err := os.ReadFile(testpki.SpecData(t, 3, "IEC_62351-4.CC.2025-11/IEC_62351-4_E2E-security.asn"))
	if err != nil {
		t.Fatal(err)
	}
	src := strings.ReplaceAll(string(raw), "\r\n", "\n")
	for _, want := range []string{"DEFINITIONS IMPLICIT TAGS", "pp        NMTOKEN (\"IEC 61850-8-1\")", "hmac           AlgorithmIdentifier {{SupportedHmacAlgorithms}},\n  time           TimeStamp",
		"iv         [0]  InitializationVector OPTIONAL", "Authenticator::= SEQUENCE {\n  nonce    OCTET STRING  OPTIONAL,\n  algo     AlgorithmIdentifier{{ Supported-ICV-Algorithms }},\n  icv      OCTET STRING"} {
		if !strings.Contains(src, want) {
			t.Fatalf("the machine-readable file no longer reads %q", want)
		}
	}
	k := newE2EPKI(t)
	ce := k.e2e(t, false, E2EOptions{ICV: []string{"kmac256"}}, nil)
	_, req, err := ce.clientHello([]byte{0xa8, 0}, 3, 7, true)
	if err != nil {
		t.Fatal(err)
	}
	var hr ccHandshakeReq
	if rest, err := asn1.Unmarshal(req, &hr); err != nil || len(rest) > 0 {
		t.Fatalf("HandshakeReq: %v", err)
	}
	tk := hr.TBS.Token1
	if hr.PP != E2EProtocol || tk.Version.At(0) != 1 || tk.DH.GroupID != 23 || tk.HMAC.Algorithm.String() != oidHMACSHA256 ||
		tk.SigAlg.Algorithm.String() != oidRSAEncryption || hr.Sign.Algo.Algorithm.String() != oidRSAEncryption ||
		tk.Conf.At(0) != 1 || tk.Conf.At(1) != 0 || time.Since(tk.Time) > time.Minute || tk.EncrMode.Tag != 0 || tk.EncrMode.Class != asn1.ClassContextSpecific {
		t.Errorf("HandshakeReq %+v", hr)
	}
	if hr.TBS.ApplData.Class != asn1.ClassUniversal || hr.TBS.ApplData.Tag != 8 {
		t.Errorf("ApplData %+v", hr.TBS.ApplData)
	}

	cs, _ := pair(t, ce, k.e2e(t, true, E2EOptions{}, nil))
	b, err := cs.wrap([]byte{0xa0, 0x03, 0x02, 0x01, 0x07})
	if err != nil {
		t.Fatal(err)
	}
	var dt asn1.RawValue
	if _, err := asn1.Unmarshal(b, &dt); err != nil || dt.Class != asn1.ClassContextSpecific || dt.Tag != 0 {
		t.Fatalf("DataTransfer %+v %v", dt, err)
	}
	var tbp ccTBP
	rest, err := asn1.Unmarshal(dt.Bytes, &tbp)
	if err != nil {
		t.Fatal(err)
	}
	var auth ccAuthenticator
	if _, err := asn1.Unmarshal(rest, &auth); err != nil || auth.Algo.Algorithm.String() != oidKMACSHAKE256 || len(auth.ICV) != 64 {
		t.Fatalf("Authenticator %+v %v", auth, err)
	}
	if tbp.Token2.AssoID != cs.assoID || tbp.Token2.Seq != 0 || tbp.ApplData.Tag != 8 {
		t.Errorf("tbp %+v", tbp)
	}
}
