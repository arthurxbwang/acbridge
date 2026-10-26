package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func hardeningCertificate(t *testing.T, names []string, cn string, leafStart, leafEnd, issuerStart, issuerEnd time.Time) fixture {
	t.Helper()
	makeKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	issuerKey, leafKey := makeKey(), makeKey()
	issuer := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "hardening issuer"}, NotBefore: issuerStart, NotAfter: issuerEnd, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuer, issuer, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err = x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn}, DNSNames: names, NotBefore: leafStart, NotAfter: leafEnd, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{cert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})), key: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), leaf: leafDER, root: issuer}
}

func validNamedCertificate(t *testing.T, names ...string) fixture {
	t.Helper()
	now := time.Now()
	return hardeningCertificate(t, names, "", now.Add(-time.Hour), now.Add(12*time.Hour), now.Add(-time.Hour), now.Add(24*time.Hour))
}

func TestUploadRejectsInvalidChainValidityWithoutMutation(t *testing.T) {
	now := time.Now()
	for _, name := range []string{"expired leaf", "future leaf", "expired issuer", "future issuer"} {
		t.Run(name, func(t *testing.T) {
			setup(t)
			admin := fakeCaddy(t, map[string]interface{}{})
			h := newHandler()
			original := validNamedCertificate(t, "a.test")
			requireStatus(t, request(t, h, "POST", "/api/open/cert", upload(original), token), 200)
			before := snapshotCache()
			disk, err := os.ReadFile(filepath.Join(certDir, snapshotName))
			if err != nil {
				t.Fatal(err)
			}
			writes := admin.writes
			leafStart, leafEnd := now.Add(-time.Hour), now.Add(time.Hour)
			issuerStart, issuerEnd := now.Add(-time.Hour), now.Add(time.Hour)
			switch name {
			case "expired leaf":
				leafStart, leafEnd = now.Add(-2*time.Hour), now.Add(-time.Hour)
			case "future leaf":
				leafStart, leafEnd = now.Add(time.Hour), now.Add(2*time.Hour)
			case "expired issuer":
				issuerStart, issuerEnd = now.Add(-2*time.Hour), now.Add(-time.Hour)
			case "future issuer":
				issuerStart, issuerEnd = now.Add(time.Hour), now.Add(2*time.Hour)
			}
			bad := hardeningCertificate(t, []string{"a.test"}, "", leafStart, leafEnd, issuerStart, issuerEnd)
			w := request(t, h, "POST", "/api/open/cert", upload(bad), token)
			requireStatus(t, w, 400)
			if !strings.Contains(w.Body.String(), "invalid_cert") {
				t.Fatal("missing actionable invalid certificate response")
			}
			after, err := os.ReadFile(filepath.Join(certDir, snapshotName))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, snapshotCache()) || !bytes.Equal(disk, after) || admin.writes != writes {
				t.Fatal("invalid validity changed cache or Caddy")
			}
		})
	}
}

func TestExpiredCacheStillRecoversAndCanRenew(t *testing.T) {
	setup(t)
	fakeCaddy(t, map[string]interface{}{})
	now := time.Now()
	old := hardeningCertificate(t, []string{"a.test"}, "", now.Add(-2*time.Hour), now.Add(-time.Hour), now.Add(-2*time.Hour), now.Add(-time.Hour))
	c, err := parsePair(old.cert, old.key)
	if err != nil {
		t.Fatal(err)
	}
	if err = persistCache(map[string]CaddyCert{"a.test": c}); err != nil {
		t.Fatal(err)
	}
	if err = loadCertsFromDisk(); err != nil {
		t.Fatalf("expiry must not prevent startup and renewal: %v", err)
	}
	if snapshotCache()["a.test"].ID != c.ID {
		t.Fatal("expired cache was discarded")
	}
	fresh := validNamedCertificate(t, "a.test")
	requireStatus(t, request(t, newHandler(), "POST", "/api/open/cert", upload(fresh), token), 200)
	if snapshotCache()["a.test"].ID != getCertID(fresh.cert) {
		t.Fatal("renewal did not replace expired cache")
	}
}

func TestReplacementRejectsLostDomainCoverage(t *testing.T) {
	setup(t)
	admin := fakeCaddy(t, map[string]interface{}{})
	h := newHandler()
	original := validNamedCertificate(t, "a.test", "b.test")
	requireStatus(t, request(t, h, "POST", "/api/open/cert", upload(original), token), 200)
	before := snapshotCache()
	disk, err := os.ReadFile(filepath.Join(certDir, snapshotName))
	if err != nil {
		t.Fatal(err)
	}
	writes := admin.writes
	shrunken := validNamedCertificate(t, "a.test", "c.test")
	w := request(t, h, "POST", "/api/open/cert", upload(shrunken), token)
	requireStatus(t, w, 409)
	if !strings.Contains(w.Body.String(), "coverage_reduction") || !strings.Contains(w.Body.String(), "b.test") {
		t.Fatal("coverage conflict must identify the lost name")
	}
	after, err := os.ReadFile(filepath.Join(certDir, snapshotName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, snapshotCache()) || !bytes.Equal(disk, after) || admin.writes != writes {
		t.Fatal("rejected replacement changed cache or Caddy")
	}
	expanded := validNamedCertificate(t, "a.test", "b.test", "c.test")
	requireStatus(t, request(t, h, "POST", "/api/open/cert", upload(expanded), token), 200)
	if err = loadCertsFromDisk(); err != nil {
		t.Fatal(err)
	}
	if len(snapshotCache()) != 3 || len(uniqueCerts(snapshotCache())) != 1 {
		t.Fatal("safe replacement did not survive recovery")
	}
}

func TestSANsAreAuthoritativeAndCanonical(t *testing.T) {
	setup(t)
	fakeCaddy(t, map[string]interface{}{})
	now := time.Now()
	f := hardeningCertificate(t, []string{"A.TEST", "a.test."}, "unrelated.test", now.Add(-time.Hour), now.Add(time.Hour), now.Add(-time.Hour), now.Add(time.Hour))
	c, err := parsePair(f.cert, f.key)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.Domains, []string{"a.test"}) {
		t.Fatalf("unexpected DNS identity: %v", c.Domains)
	}
	h := newHandler()
	requireStatus(t, request(t, h, "POST", "/api/open/cert", upload(f), token), 200)
	other := hardeningCertificate(t, []string{"b.test"}, "a.test", now.Add(-time.Hour), now.Add(time.Hour), now.Add(-time.Hour), now.Add(time.Hour))
	requireStatus(t, request(t, h, "POST", "/api/open/cert", upload(other), token), 200)
	if len(uniqueCerts(snapshotCache())) != 2 || snapshotCache()["a.test"].ID != c.ID {
		t.Fatal("a nonauthoritative CN replaced an unrelated certificate")
	}
}

func TestWildcardReplacementCoverage(t *testing.T) {
	for _, tc := range []struct {
		name             string
		old, replacement []string
		status           int
	}{
		{"wildcard covers exact domain", []string{"a.test", "b.test"}, []string{"a.test", "*.test"}, 200},
		{"exact names do not replace wildcard scope", []string{"a.test", "*.test"}, []string{"a.test", "b.test"}, 409},
		{"wildcard covers one label only", []string{"a.test", "deep.b.test"}, []string{"a.test", "*.test"}, 409},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setup(t)
			fakeCaddy(t, map[string]interface{}{})
			h := newHandler()
			requireStatus(t, request(t, h, "POST", "/api/open/cert", upload(validNamedCertificate(t, tc.old...)), token), 200)
			requireStatus(t, request(t, h, "POST", "/api/open/cert", upload(validNamedCertificate(t, tc.replacement...)), token), tc.status)
		})
	}
}
