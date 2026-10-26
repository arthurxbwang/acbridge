package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, address, apiToken, admin string
		seconds                        int
		options                        runtimeOptions
		valid                          bool
	}{
		{"proxy", "127.0.0.1:9443", "test-token", "http://127.0.0.1:2019", 30, runtimeOptions{HTTP: true}, true},
		{"ipv6 proxy", "[::1]:9443", "test-token", "http://127.0.0.1:2019", 30, runtimeOptions{HTTP: true}, true},
		{"TLS", ":9443", "test-token", "https://caddy.example", 30, runtimeOptions{CertFile: "cert", KeyFile: "key"}, true},
		{"no token", "127.0.0.1:9443", "", "http://127.0.0.1:2019", 30, runtimeOptions{HTTP: true}, false},
		{"legacy default token", "127.0.0.1:9443", "acbridge-secret-token", "http://127.0.0.1:2019", 30, runtimeOptions{HTTP: true}, false},
		{"public HTTP", "0.0.0.0:9443", "test-token", "http://127.0.0.1:2019", 30, runtimeOptions{HTTP: true}, false},
		{"DNS HTTP", "localhost:9443", "test-token", "http://127.0.0.1:2019", 30, runtimeOptions{HTTP: true}, false},
		{"missing mode", "127.0.0.1:9443", "test-token", "http://127.0.0.1:2019", 30, runtimeOptions{}, false},
		{"incomplete TLS", "127.0.0.1:9443", "test-token", "http://127.0.0.1:2019", 30, runtimeOptions{CertFile: "cert"}, false},
		{"conflicting TLS", "127.0.0.1:9443", "test-token", "http://127.0.0.1:2019", 30, runtimeOptions{CertFile: "cert", KeyFile: "key", DevSelfSigned: true}, false},
		{"conflicting HTTP", "127.0.0.1:9443", "test-token", "http://127.0.0.1:2019", 30, runtimeOptions{HTTP: true, DevSelfSigned: true}, false},
		{"zero interval", "127.0.0.1:9443", "test-token", "http://127.0.0.1:2019", 0, runtimeOptions{HTTP: true}, false},
		{"overflow interval", "127.0.0.1:9443", "test-token", "http://127.0.0.1:2019", 86401, runtimeOptions{HTTP: true}, false},
		{"invalid admin scheme", "127.0.0.1:9443", "test-token", "file:///tmp/config", 30, runtimeOptions{HTTP: true}, false},
		{"inline credentials", "127.0.0.1:9443", "test-token", "http://username:secret@127.0.0.1:2019", 30, runtimeOptions{HTTP: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRuntimeOptions(tc.address, tc.apiToken, tc.admin, tc.seconds, tc.options)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t error=%v", tc.valid, err)
			}
		})
	}
}

func TestHealthAuthenticationAndRecovery(t *testing.T) {
	setup(t)
	syncHealth.Lock()
	syncHealth.status = runtimeStatus{}
	syncHealth.Unlock()
	h := wrapRuntimeHandler(newHandler())
	for _, path := range []string{"/readyz", "/status"} {
		requireStatus(t, request(t, h, "GET", path, nil, ""), http.StatusUnauthorized)
		requireStatus(t, request(t, h, "POST", path, nil, token), http.StatusMethodNotAllowed)
	}
	requireStatus(t, request(t, h, "GET", "/readyz", nil, token), http.StatusServiceUnavailable)
	recordSyncResult(errors.New("Caddy Admin GET /config/: transport failure"))
	w := request(t, h, "GET", "/status", nil, token)
	if !strings.Contains(w.Body.String(), `"pending_sync":true`) || !strings.Contains(w.Body.String(), "transport failure") {
		t.Fatal("failure status must identify pending sync")
	}
	recordSyncResult(nil)
	requireStatus(t, request(t, h, "GET", "/readyz", nil, token), http.StatusOK)
	markSyncPending()
	requireStatus(t, request(t, h, "GET", "/readyz", nil, token), http.StatusServiceUnavailable)
	recordSyncResult(nil)
	requireStatus(t, request(t, h, "GET", "/readyz", nil, token), http.StatusOK)
	syncHealth.Lock()
	old := time.Now().Add(-48 * time.Hour)
	syncHealth.status.LastSuccess = &old
	syncHealth.Unlock()
	requireStatus(t, request(t, h, "GET", "/readyz", nil, token), http.StatusServiceUnavailable)
	// An unauthenticated health request must not disclose cached domain metadata.
	replaceCache(map[string]CaddyCert{"private.example": {Domains: []string{"private.example"}}})
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("GET", "/", nil))
	if r.Code != 200 || strings.Contains(r.Body.String(), "private.example") || strings.Contains(r.Body.String(), "Expires") {
		t.Fatal("home must be a minimal liveness response")
	}
}

func TestRuntimeTLSAndShutdown(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key")
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	srv, err := newRuntimeServer("127.0.0.1:0", http.HandlerFunc(handleHome), runtimeOptions{CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveRuntimeListener(ctx, srv, listener, false) }()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}}}
	defer client.CloseIdleConnections()
	res, err := client.Get("https://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("TLS request: status=%d error=%v", res.StatusCode, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not gracefully shut down")
	}
}

func TestCertificateListDoesNotInventTrust(t *testing.T) {
	setup(t)
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	replaceCache(map[string]CaddyCert{"localhost": {
		ID: 123, Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})), Domains: []string{"localhost"},
	}})
	w := request(t, newHandler(), "GET", "/api/open/cert", nil, token)
	var result struct {
		Data CertListData `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Data.Nodes) != 1 {
		t.Fatal("missing cached certificate")
	}
	node := result.Data.Nodes[0]
	if node.Trusted || node.TrustStatus != "not_verified" || !node.SelfSignature {
		t.Fatal("certificate metadata must identify self-signing without claiming trust")
	}
}
