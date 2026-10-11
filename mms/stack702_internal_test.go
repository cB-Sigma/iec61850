package mms

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

// AP titles and AE qualifiers are read in both forms: form 2 (object
// identifier, integer) and form 1 (directory name, relative
// distinguished name), and the AARE carries the responding AP title and
// AE qualifier (IEC 60870-6-702:2014 Table A.58; IEC 62351-4 10.5.3).
// Covers: SIG-IPE-1914
func TestAETitleForms(t *testing.T) {
	if s, f := decodeAPTitle(Elem{Tag: 0xa6, Val: T(0x06, OID("1.3.9999.1"))}); s != "1.3.9999.1" || f != 2 {
		t.Errorf("form 2 = %q %d", s, f)
	}
	name := pkix.Name{Country: []string{"IN"}, Organization: []string{"Grid-India"}, CommonName: "rldc"}
	der, err := asn1.Marshal(name.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	if s, f := decodeAPTitle(Elem{Tag: 0xa6, Val: der}); s != "CN=rldc,O=Grid-India,C=IN" || f != 1 {
		t.Errorf("form 1 = %q %d", s, f)
	}
	if q, n := decodeAEQualifier(Elem{Tag: 0xa7, Val: Int(0x02, 12)}); q == nil || *q != 12 || n != "" {
		t.Errorf("qualifier form 2 = %v %q", q, n)
	}
	rdn, _ := asn1.Marshal(pkix.RelativeDistinguishedNameSET{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "scada"}})
	if q, n := decodeAEQualifier(Elem{Tag: 0xa7, Val: rdn}); q != nil || n != "CN=scada" {
		t.Errorf("qualifier form 1 = %v %q", q, n)
	}
	f, err := acseFields(aare(ACSEAccepted, 0, nil, nil, T(0xa4, T(0x06, OID("1.3.9999.2"))), T(0xa5, Int(0x02, 12))), 0x61)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := decodeAPTitle(f[0xa4]); s != "1.3.9999.2" {
		t.Errorf("responding AP title %q", s)
	}
	if q, _ := decodeAEQualifier(f[0xa5]); q == nil || *q != 12 {
		t.Errorf("responding AE qualifier %v", q)
	}
}
