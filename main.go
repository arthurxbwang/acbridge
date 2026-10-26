package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Configuration variables
var (
	addr         string
	token        string
	caddyURL     string
	certDir      string
	syncInterval time.Duration
	httpClient   = &http.Client{Timeout: 10 * time.Second}
	cacheMutex   sync.RWMutex
	certCache    = make(map[string]CaddyCert) // Keyed by domain name
)

type CaddyCert struct {
	Certificate string    `json:"certificate"`
	Key         string    `json:"key"`
	Domains     []string  `json:"-"`
	NotAfter    time.Time `json:"-"`
	Issuer      string    `json:"-"`
	ID          int64     `json:"-"`
	LegacyIDs   []int64   `json:"legacy_ids,omitempty"`
}

type CertResponse struct {
	Data interface{} `json:"data"`
	Err  string      `json:"err"`
	Msg  string      `json:"msg"`
}

type UpsertCertRequest struct {
	ID     int64 `json:"id"`
	Type   int   `json:"type"`
	Manual struct {
		Crt string `json:"crt"`
		Key string `json:"key"`
	} `json:"manual"`
}

type CertNode struct {
	AcmeMessage   string   `json:"acme_message"`
	Domains       []string `json:"domains"`
	Expired       bool     `json:"expired"`
	ID            int64    `json:"id"`
	Issuer        string   `json:"issuer"`
	RelatedSites  []string `json:"related_sites"`
	Revoked       bool     `json:"revoked"`
	SelfSignature bool     `json:"self_signature"`
	Trusted       bool     `json:"trusted"`
	TrustStatus   string   `json:"trust_status"`
	Type          int      `json:"type"`
	ValidBefore   string   `json:"valid_before"`
}

type CertListData struct {
	Nodes []CertNode `json:"nodes"`
	Total int        `json:"total"`
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	flag.StringVar(&addr, "addr", "127.0.0.1:9443", "Address to listen on")
	flag.StringVar(&token, "token", "", "API token (prefer ACBRIDGE_TOKEN to keep credentials out of process arguments)")
	flag.StringVar(&caddyURL, "caddy", "http://127.0.0.1:2019", "Caddy Admin API base URL")
	flag.StringVar(&certDir, "cert-dir", "./certs", "Directory to store certificate cache files")
	var syncSec int
	var options runtimeOptions
	var printVersion bool
	flag.IntVar(&syncSec, "sync-interval", 30, "Positive interval in seconds to sync certificates with Caddy")
	flag.StringVar(&options.CertFile, "tls-cert", "", "HTTPS certificate chain file")
	flag.StringVar(&options.KeyFile, "tls-key", "", "HTTPS private key file")
	flag.BoolVar(&options.HTTP, "http", false, "Serve HTTP on loopback only, behind a trusted HTTPS reverse proxy")
	flag.BoolVar(&options.DevSelfSigned, "dev-self-signed", false, "Explicit development-only ephemeral self-signed HTTPS")
	flag.BoolVar(&printVersion, "version", false, "Print version and exit")
	flag.Parse()
	if printVersion {
		fmt.Printf("acbridge %s (%s)\n", version, commit)
		return nil
	}
	if envToken := os.Getenv("ACBRIDGE_TOKEN"); envToken != "" {
		token = envToken
	}
	if err := validateRuntimeOptions(addr, token, caddyURL, syncSec, options); err != nil {
		return err
	}
	syncInterval = time.Duration(syncSec) * time.Second
	server, err := newRuntimeServer(addr, wrapRuntimeHandler(newHandler()), options)
	if err != nil {
		return err
	}
	// Reserve the address before touching the cache or Caddy. A second process
	// must not synchronize an empty cache and only then discover a port conflict.
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("create certificate cache: %w", err)
	}
	if err := loadCertsFromDisk(); err != nil {
		return fmt.Errorf("cannot safely load certificate cache: %w", err)
	}
	if err := syncWithCaddy(); err != nil {
		log.Printf("Initial sync failed; /readyz will report unavailable: %v", err)
	}
	go startSyncLoop()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveRuntimeListener(ctx, server, listener, options.HTTP)
}

// authMiddleware checks the X-SLCE-API-TOKEN header
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqToken := r.Header.Get("X-SLCE-API-TOKEN")
		if token == "" || subtle.ConstantTimeCompare([]byte(reqToken), []byte(token)) != 1 {
			log.Printf("Unauthorized request from %s: invalid or missing token", r.RemoteAddr)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(CertResponse{
				Err: "unauthorized",
				Msg: "Invalid API Token",
			})
			return
		}
		next(w, r)
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "acbridge is running")
}

func handleCert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		handleListCerts(w, r)
	case http.MethodPost:
		handleUpsertCert(w, r)
	case http.MethodDelete:
		handleDeleteCert(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(CertResponse{
			Err: "method_not_allowed",
			Msg: "Method not allowed",
		})
	}
}

// handleListCerts maps to GET /open/cert
func handleListCerts(w http.ResponseWriter, r *http.Request) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	// Deduplicate certs in response (since a single cert might cover multiple domains)
	seenCerts := make(map[int64]CertNode)
	for _, cert := range certCache {
		if _, seen := seenCerts[cert.ID]; seen {
			continue
		}

		expired := time.Now().After(cert.NotAfter)
		selfSigned := false
		if block, _ := pem.Decode([]byte(cert.Certificate)); block != nil {
			if leaf, err := x509.ParseCertificate(block.Bytes); err == nil {
				selfSigned = leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
			}
		}
		node := CertNode{
			AcmeMessage:   "",
			Domains:       cert.Domains,
			Expired:       expired,
			ID:            cert.ID,
			Issuer:        cert.Issuer,
			RelatedSites:  cert.Domains, // Map domains as sites
			Revoked:       false,
			SelfSignature: selfSigned,
			Trusted:       false,
			TrustStatus:   "not_verified",
			Type:          0, // 0 = manual cert usually
			ValidBefore:   cert.NotAfter.Format("2006-01-02 15:04:05"),
		}
		seenCerts[cert.ID] = node
	}

	nodes := make([]CertNode, 0, len(seenCerts))
	for _, node := range seenCerts {
		nodes = append(nodes, node)
	}

	json.NewEncoder(w).Encode(CertResponse{
		Data: CertListData{
			Nodes: nodes,
			Total: len(nodes),
		},
		Err: "",
		Msg: "",
	})
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"acbridge Mock WAF"},
		},
		NotBefore:             notBefore.Add(-time.Minute),
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}
