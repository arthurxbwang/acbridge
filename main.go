package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"sync"
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
	Type          int      `json:"type"`
	ValidBefore   string   `json:"valid_before"`
}

type CertListData struct {
	Nodes []CertNode `json:"nodes"`
	Total int        `json:"total"`
}

func main() {
	flag.StringVar(&addr, "addr", ":9443", "Address to listen on (e.g. :9443 or 0.0.0.0:9443)")
	flag.StringVar(&token, "token", "acbridge-secret-token", "API Token for authentication (X-SLCE-API-TOKEN header)")
	flag.StringVar(&caddyURL, "caddy", "http://127.0.0.1:2019", "Caddy Admin API base URL")
	flag.StringVar(&certDir, "cert-dir", "./certs", "Directory to store certificate cache files")
	var syncSec int
	flag.IntVar(&syncSec, "sync-interval", 30, "Interval in seconds to sync certificates with Caddy")
	flag.Parse()

	// Override token from environment variable if present
	if envToken := os.Getenv("ACBRIDGE_TOKEN"); envToken != "" {
		token = envToken
	}

	log.Printf("================ acbridge starting ================")
	log.Printf("Listening on: %s", addr)
	log.Print("API Token   : configured (value hidden)")
	log.Printf("Caddy URL   : %s", caddyURL)
	log.Printf("Cert Cache  : %s", certDir)
	log.Printf("Sync Every  : %d seconds", syncSec)
	log.Printf("===================================================")

	if syncSec <= 0 {
		log.Fatal("sync-interval must be positive")
	}
	syncInterval = time.Duration(syncSec) * time.Second

	// 1. Create cert directory
	if err := os.MkdirAll(certDir, 0755); err != nil {
		log.Fatalf("Failed to create cert directory: %v", err)
	}

	// 2. Load cached certs from disk
	if err := loadCertsFromDisk(); err != nil {
		log.Fatalf("Cannot safely load certificate cache: %v", err)
	}

	// 3. Initial sync with Caddy
	if err := syncWithCaddy(); err != nil {
		log.Printf("Initial sync with Caddy failed: %v (make sure Caddy is running and admin API is enabled)", err)
	} else {
		log.Println("Initial sync with Caddy succeeded!")
	}

	// 4. Start periodic sync routine
	go startSyncLoop()

	// Use a dedicated mux so protocol endpoints are testable.
	mux := newHandler()

	// Generate self-signed cert for HTTPS
	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate self-signed cert: %v", err)
	}

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		},
	}

	log.Printf("Listening on (HTTPS): %s", addr)
	log.Fatal(server.ListenAndServeTLS("", ""))
}

// authMiddleware checks the X-SLCE-API-TOKEN header
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqToken := r.Header.Get("X-SLCE-API-TOKEN")
		if reqToken != token {
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
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "acbridge - AllinSSL to Caddy Bridge is running.\n")
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	fmt.Fprintf(w, "Cached domains count: %d\n", len(certCache))
	for domain, cert := range certCache {
		fmt.Fprintf(w, " - %s (Expires: %s, Issuer: %s)\n", domain, cert.NotAfter.Format(time.RFC3339), cert.Issuer)
	}
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
		node := CertNode{
			AcmeMessage:   "",
			Domains:       cert.Domains,
			Expired:       expired,
			ID:            cert.ID,
			Issuer:        cert.Issuer,
			RelatedSites:  cert.Domains, // Map domains as sites
			Revoked:       false,
			SelfSignature: false,
			Trusted:       true,
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
		NotBefore:             notBefore,
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
