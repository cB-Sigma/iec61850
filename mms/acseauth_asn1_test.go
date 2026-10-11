package mms

import (
	"bytes"
	"encoding/asn1"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iec61850/internal/testpki"
)

// certBased is MMS-Authentication-value certificate-based of the IEC
// 62351-4 machine-readable file module STASE-MMS-Authentication-value (2025-11,
// IMPLICIT TAGS), mapped to encoding/asn1 independently of acseauth.go.
type certBased struct {
	Cert      []byte    `asn1:"tag:0"`
	Time      time.Time `asn1:"generalized,tag:1"`
	Signature []byte    `asn1:"tag:2"`
}

// The A-security profile's authentication value, as our client (AARQ) and
// server (AARE) send it, decodes with the official ASN.1 of the IEC
// 62351-4 machine-readable files (2025-11): external [2] IMPLICIT with the
// indirect reference and single-ASN1-type [0] (explicit, the type is a
// CHOICE) holding certificate-based [0] IMPLICIT SEQUENCE { [0] certificate,
// [1] GeneralizedTime, [2] signature }; and a value built from that ASN.1
// by an independent encoder decodes with ours. The module still makes the
// identification mandatory, which F-838 departs from.
// Covers: SIG-IPE-2912
func TestAuthenticationValueMatchesCodeComponentASN1(t *testing.T) {
	src, err := os.ReadFile(testpki.SpecData(t, 3, "IEC_62351-4.CC.2025-11/IEC_62351-4_First-edition.asn"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"DEFINITIONS IMPLICIT TAGS", "external           [2] IMPLICIT SEQUENCE", "indirect-reference   INTEGER",
		"single-ASN1-type [0] MMS-Authentication-value", "certificate-based          [0]  IMPLICIT SEQUENCE",
		"authentication-Certificate [0]  IMPLICIT SignatureCertificate", "time                       [1]  IMPLICIT GeneralizedTime",
		"signature                  [2]  IMPLICIT SignedValue"} {
		if !strings.Contains(string(src), want) {
			t.Fatalf("the machine-readable file no longer reads %q: the mapping below needs review", want)
		}
	}
	when := time.Date(2026, 9, 25, 10, 11, 12, 345e6, time.UTC)
	ours := encodeAuthValue(authValue{cert: []byte{0x30, 0x03, 0x02, 0x01, 0x01}, time: authTime(when), signature: []byte{9, 8, 7}, pci: 3})

	var ext asn1.RawValue
	if rest, err := asn1.Unmarshal(ours, &ext); err != nil || len(rest) > 0 || ext.Class != asn1.ClassContextSpecific || ext.Tag != 2 || !ext.IsCompound {
		t.Fatalf("external: %+v %v", ext, err)
	}
	var pci int
	rest, err := asn1.Unmarshal(ext.Bytes, &pci)
	if err != nil || pci != 3 {
		t.Fatalf("indirect-reference %d %v", pci, err)
	}
	var single asn1.RawValue
	if rest, err = asn1.Unmarshal(rest, &single); err != nil || len(rest) > 0 || single.Class != asn1.ClassContextSpecific || single.Tag != 0 || !single.IsCompound {
		t.Fatalf("single-ASN1-type: %+v %v", single, err)
	}
	var cb certBased
	if rest, err := asn1.UnmarshalWithParams(single.Bytes, &cb, "tag:0"); err != nil || len(rest) > 0 {
		t.Fatalf("certificate-based: %v", err)
	}
	if !cb.Time.Equal(when) || !bytes.Equal(cb.Signature, []byte{9, 8, 7}) || len(cb.Cert) != 5 {
		t.Errorf("decoded %+v", cb)
	}

	// The other way: a value encoded from the ASN.1 by encoding/asn1
	// (which writes GeneralizedTime without fractions).
	when = when.Truncate(time.Second)
	inner, err := asn1.MarshalWithParams(certBased{Cert: []byte{0x30, 0}, Time: when, Signature: []byte{1}}, "tag:0")
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner})
	id, _ := asn1.Marshal(5)
	theirs, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: append(id, enc...)})
	v, err := decodeAuthValue(theirs)
	if err != nil {
		t.Fatal(err)
	}
	if v.pci != 5 || !bytes.Equal(v.signature, []byte{1}) {
		t.Errorf("decoded %+v", v)
	}
	if got, err := parseAuthTime(v.time); err != nil || !got.Equal(when) {
		t.Errorf("time %s: %v %v", v.time, got, err)
	}
}
