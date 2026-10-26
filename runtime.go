package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Set by release builds; development builds remain identifiable.
var version = "dev"
var commit = "unknown"

type runtimeOptions struct {
	HTTP          bool
	DevSelfSigned bool
	CertFile      string
	KeyFile       string
}

func validateRuntimeOptions(address, apiToken, adminURL string, seconds int, options runtimeOptions) error {
	if strings.TrimSpace(apiToken) == "" || apiToken == "acbridge-secret-token" {
		return errors.New("configure a non-default ACBRIDGE_TOKEN before starting")
	}
	if seconds <= 0 || int64(seconds) > int64((24*time.Hour)/time.Second) {
		return errors.New("sync-interval must be between 1 and 86400 seconds")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return errors.New("addr must contain a host and port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("addr port must be between 1 and 65535")
	}
	if options.HTTP {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return errors.New("-http requires a literal loopback listen address, such as 127.0.0.1:9443")
		}
		if options.CertFile != "" || options.KeyFile != "" || options.DevSelfSigned {
			return errors.New("-http cannot be combined with HTTPS options")
		}
	} else {
		if (options.CertFile == "") != (options.KeyFile == "") {
			return errors.New("both -tls-cert and -tls-key are required")
		}
		if options.CertFile == "" && !options.DevSelfSigned {
			return errors.New("configure -tls-cert and -tls-key, or use -http behind a loopback HTTPS proxy; development only: -dev-self-signed")
		}
		if options.CertFile != "" && options.DevSelfSigned {
			return errors.New("-dev-self-signed cannot be combined with certificate files")
		}
	}
	u, err := url.Parse(adminURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("caddy must be an HTTP(S) Admin URL without inline credentials, query or fragment")
	}
	return nil
}

func newRuntimeServer(address string, handler http.Handler, options runtimeOptions) (*http.Server, error) {
	server := &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      100 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	if options.HTTP {
		return server, nil
	}
	var cert tls.Certificate
	var err error
	if options.DevSelfSigned {
		cert, err = generateSelfSignedCert()
		log.Print("Development-only ephemeral self-signed TLS enabled")
	} else {
		cert, err = tls.LoadX509KeyPair(options.CertFile, options.KeyFile)
	}
	if err != nil {
		return nil, fmt.Errorf("load HTTPS certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, errors.New("cannot parse HTTPS leaf certificate")
	}
	if time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return nil, errors.New("HTTPS certificate is expired or not yet valid")
	}
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		return nil, errors.New("HTTPS certificate must contain a DNS or IP subject alternative name")
	}
	server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	return server, nil
}

func serveRuntime(ctx context.Context, server *http.Server, plainHTTP bool) error {
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	return serveRuntimeListener(ctx, server, listener, plainHTTP)
}

func serveRuntimeListener(ctx context.Context, server *http.Server, listener net.Listener, plainHTTP bool) error {
	result := make(chan error, 1)
	go func() {
		if plainHTTP {
			result <- server.Serve(listener)
		} else {
			result <- server.ServeTLS(listener, "", "")
		}
	}()
	log.Printf("Listening on %s; authenticated readiness at /readyz", listener.Addr())
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			server.Close()
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	}
}

type runtimeStatus struct {
	Ready        bool       `json:"ready"`
	PendingSync  bool       `json:"pending_sync"`
	LastAttempt  *time.Time `json:"last_attempt,omitempty"`
	LastSuccess  *time.Time `json:"last_success,omitempty"`
	LastError    string     `json:"last_error,omitempty"`
	Certificates int        `json:"certificates"`
	Domains      int        `json:"domains"`
	Version      string     `json:"version"`
}

var syncHealth = struct {
	sync.RWMutex
	status runtimeStatus
}{}

// Called after changing durable desired state, before starting network sync.
func markSyncPending() {
	syncHealth.Lock()
	defer syncHealth.Unlock()
	syncHealth.status.Ready = false
	syncHealth.status.PendingSync = true
}

func recordSyncResult(err error) {
	now := time.Now().UTC()
	syncHealth.Lock()
	defer syncHealth.Unlock()
	syncHealth.status.LastAttempt = &now
	syncHealth.status.Ready = err == nil
	syncHealth.status.PendingSync = err != nil
	if err == nil {
		syncHealth.status.LastSuccess = &now
		syncHealth.status.LastError = ""
	} else {
		syncHealth.status.LastError = err.Error()
	}
}

func getRuntimeStatus() runtimeStatus {
	syncHealth.RLock()
	status := syncHealth.status
	syncHealth.RUnlock()
	// A stalled loop must not keep reporting a stale success indefinitely.
	maxAge := 2*syncInterval + 90*time.Second
	if status.LastSuccess == nil || time.Since(*status.LastSuccess) > maxAge {
		status.Ready = false
		status.PendingSync = true
	}
	cache := snapshotCache()
	status.Domains = len(cache)
	status.Certificates = len(uniqueCerts(cache))
	status.Version = version
	return status
}

func wrapRuntimeHandler(next http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", next)
	mux.HandleFunc("/readyz", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		status := getRuntimeStatus()
		if !status.Ready {
			reply(w, http.StatusServiceUnavailable, status, "not_ready", "Caddy synchronization is not ready")
			return
		}
		reply(w, http.StatusOK, status, "", "")
	}))
	mux.HandleFunc("/status", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		reply(w, http.StatusOK, getRuntimeStatus(), "", "")
	}))
	return mux
}
