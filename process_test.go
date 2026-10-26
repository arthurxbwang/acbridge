package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the actual entry point: flags, listeners, TLS, persistence and shutdown.
func TestProcessLifecycle(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "acbridge")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	cleanEnv := []string{}
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "ACBRIDGE_TOKEN=") {
			cleanEnv = append(cleanEnv, e)
		}
	}
	for _, tc := range []struct {
		name     string
		args     []string
		hasToken bool
	}{
		{"missing-token", []string{"-http"}, false},
		{"missing-transport", nil, true},
		{"public-cleartext", []string{"-http", "-addr", "0.0.0.0:9443"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, tc.args...)
			cmd.Env = append([]string{}, cleanEnv...)
			if tc.hasToken {
				cmd.Env = append(cmd.Env, "ACBRIDGE_TOKEN=process-test-token")
			}
			if err := cmd.Run(); err == nil {
				t.Fatal("unsafe startup accepted")
			}
			if ctx.Err() != nil {
				t.Fatal("invalid startup did not fail promptly")
			}
		})
	}
	t.Run("occupied-port-does-not-change-state", func(t *testing.T) {
		setup(t)
		admin := fakeCaddy(t, map[string]interface{}{})
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		dir := filepath.Join(t.TempDir(), "new-cache")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, "-http", "-addr", listener.Addr().String(), "-caddy", caddyURL, "-cert-dir", dir)
		cmd.Env = append(append([]string{}, cleanEnv...), "ACBRIDGE_TOKEN=process-test-token")
		if err := cmd.Run(); err == nil || ctx.Err() != nil {
			t.Fatal("occupied port must fail promptly")
		}
		admin.mu.Lock()
		writes := admin.writes
		admin.mu.Unlock()
		if writes != 0 {
			t.Fatal("failed startup changed Caddy configuration")
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("failed startup created cache directory")
		}
	})
	start := func(t *testing.T, args ...string) func() {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Env = append(append([]string{}, cleanEnv...), "ACBRIDGE_TOKEN=process-test-token")
		log, err := os.Create(filepath.Join(t.TempDir(), "process.log"))
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			_ = cmd.Process.Signal(os.Interrupt)
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("graceful shutdown: %v", err)
				}
			case <-time.After(20 * time.Second):
				_ = cmd.Process.Kill()
				<-done
				t.Error("shutdown timed out")
			}
			log.Close()
		}
		t.Cleanup(stop)
		return stop
	}
	get := func(t *testing.T, client *http.Client, base, path string, auth bool) (int, []byte) {
		t.Helper()
		var res *http.Response
		var err error
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			req, e := http.NewRequest("GET", base+path, nil)
			if e != nil {
				t.Fatal(e)
			}
			if auth {
				req.Header.Set("X-SLCE-API-TOKEN", "process-test-token")
			}
			res, err = client.Do(req)
			if err == nil {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		if err != nil || res == nil {
			t.Fatalf("process endpoint unavailable: %v", err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, data
	}
	t.Run("http-upload-restart", func(t *testing.T) {
		setup(t)
		fakeCaddy(t, map[string]interface{}{})
		dir := t.TempDir()
		address := unusedAddress(t)
		base := "http://" + address
		args := []string{"-http", "-addr", address, "-caddy", caddyURL, "-cert-dir", dir, "-sync-interval", "1"}
		stop := start(t, args...)
		client := &http.Client{Timeout: time.Second}
		defer client.CloseIdleConnections()
		if code, _ := get(t, client, base, "/readyz", true); code != 200 {
			t.Fatalf("ready status %d", code)
		}
		if code, _ := get(t, client, base, "/status", false); code != 401 {
			t.Fatalf("unauth status %d", code)
		}
		data, _ := json.Marshal(upload(certificates(t, 91)))
		req, _ := http.NewRequest("POST", base+"/api/open/cert", bytes.NewReader(data))
		req.Header.Set("X-SLCE-API-TOKEN", "process-test-token")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("upload status %d", res.StatusCode)
		}
		if _, body := get(t, client, base, "/", false); bytes.Contains(body, []byte("bridge.test")) {
			t.Fatal("home disclosed certificate names")
		}
		client.CloseIdleConnections()
		stop()
		start(t, args...)
		if code, body := get(t, client, base, "/api/open/cert", true); code != 200 || !bytes.Contains(body, []byte("bridge.test")) {
			t.Fatal("restart lost persisted certificate")
		}
	})
	t.Run("trusted-tls", func(t *testing.T) {
		setup(t)
		fakeCaddy(t, map[string]interface{}{})
		cert := certificates(t, 92)
		dir := t.TempDir()
		crt, key := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
		if err := os.WriteFile(crt, []byte(cert.cert), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(key, []byte(cert.key), 0600); err != nil {
			t.Fatal(err)
		}
		address := unusedAddress(t)
		base := "https://" + address
		start(t, "-addr", address, "-tls-cert", crt, "-tls-key", key, "-caddy", caddyURL, "-cert-dir", filepath.Join(dir, "cache"))
		roots := x509.NewCertPool()
		roots.AddCert(cert.root)
		client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "bridge.test"}}}
		defer client.CloseIdleConnections()
		if code, _ := get(t, client, base, "/readyz", true); code != 200 {
			t.Fatalf("TLS readiness %d", code)
		}
	})
	t.Run("unavailable-caddy-is-not-ready", func(t *testing.T) {
		admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
		defer admin.Close()
		address := unusedAddress(t)
		base := "http://" + address
		start(t, "-http", "-addr", address, "-caddy", admin.URL, "-cert-dir", t.TempDir())
		client := &http.Client{Timeout: time.Second}
		defer client.CloseIdleConnections()
		if code, _ := get(t, client, base, "/", false); code != 200 {
			t.Fatalf("liveness %d", code)
		}
		if code, _ := get(t, client, base, "/readyz", true); code != 503 {
			t.Fatalf("unready status %d", code)
		}
	})
}
