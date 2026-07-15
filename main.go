package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Configuration variables
var (
	addr          string
	token         string
	caddyURL      string
	certDir       string
	syncInterval  time.Duration
	httpClient    = &http.Client{Timeout: 10 * time.Second}
	cacheMutex    sync.RWMutex
	certCache     = make(map[string]CaddyCert) // Keyed by domain name
)

type CaddyCert struct {
	Certificate string    `json:"certificate"`
	Key         string    `json:"key"`
	Domains     []string  `json:"-"`
	NotAfter    time.Time `json:"-"`
	Issuer      string    `json:"-"`
	ID          int64     `json:"-"`
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
	log.Printf("API Token   : %s", token)
	log.Printf("Caddy URL   : %s", caddyURL)
	log.Printf("Cert Cache  : %s", certDir)
	log.Printf("Sync Every  : %d seconds", syncSec)
	log.Printf("===================================================")

	syncInterval = time.Duration(syncSec) * time.Second

	// 1. Create cert directory
	if err := os.MkdirAll(certDir, 0755); err != nil {
		log.Fatalf("Failed to create cert directory: %v", err)
	}

	// 2. Load cached certs from disk
	if err := loadCertsFromDisk(); err != nil {
		log.Printf("Error loading cached certs: %v", err)
	}

	// 3. Initial sync with Caddy
	if err := syncWithCaddy(); err != nil {
		log.Printf("Initial sync with Caddy failed: %v (make sure Caddy is running and admin API is enabled)", err)
	} else {
		log.Println("Initial sync with Caddy succeeded!")
	}

	// 4. Start periodic sync routine
	go startSyncLoop()

	// 5. Register HTTP handlers
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/open/cert", authMiddleware(handleCert))
	http.HandleFunc("/open/cert/", authMiddleware(handleCert))
	http.HandleFunc("/api/open/cert", authMiddleware(handleCert))
	http.HandleFunc("/api/open/cert/", authMiddleware(handleCert))

	log.Fatal(http.ListenAndServe(addr, nil))
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

// handleUpsertCert maps to POST /open/cert
func handleUpsertCert(w http.ResponseWriter, r *http.Request) {
	var req UpsertCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Failed to decode upsert request: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(CertResponse{Err: "bad_request", Msg: "Failed to parse request JSON"})
		return
	}

	crtPEM := req.Manual.Crt
	keyPEM := req.Manual.Crt // Fallback
	if req.Manual.Key != "" {
		keyPEM = req.Manual.Key
	}

	if crtPEM == "" || keyPEM == "" {
		log.Println("Invalid request: certificate or key is empty")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(CertResponse{Err: "bad_request", Msg: "Certificate and key cannot be empty"})
		return
	}

	// Parse certificate to validate and get domains, expiry
	domains, notAfter, issuer, err := parsePEMCert(crtPEM)
	if err != nil {
		log.Printf("Failed to parse certificate: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(CertResponse{Err: "invalid_cert", Msg: fmt.Sprintf("Failed to parse certificate: %v", err)})
		return
	}

	certID := getCertID(crtPEM)
	log.Printf("Received certificate for domains: %s (ID: %d)", strings.Join(domains, ", "), certID)

	caddyCert := CaddyCert{
		Certificate: crtPEM,
		Key:         keyPEM,
		Domains:     domains,
		NotAfter:    notAfter,
		Issuer:      issuer,
		ID:          certID,
	}

	// Write to disk cache
	if err := saveCertToDisk(caddyCert); err != nil {
		log.Printf("Failed to save cert to disk: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(CertResponse{Err: "internal_error", Msg: "Failed to cache certificate on disk"})
		return
	}

	// Update local memory cache
	cacheMutex.Lock()
	for _, domain := range domains {
		certCache[domain] = caddyCert
	}
	cacheMutex.Unlock()

	// Sync with Caddy immediately
	if err := syncWithCaddy(); err != nil {
		log.Printf("Sync with Caddy failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(CertResponse{Err: "caddy_sync_failed", Msg: fmt.Sprintf("Failed to apply certificate to Caddy: %v", err)})
		return
	}

	log.Printf("Successfully deployed certificate %d to Caddy", certID)
	json.NewEncoder(w).Encode(CertResponse{
		Data: certID,
		Err:  "",
		Msg:  "Certificate deployed and applied successfully",
	})
}

// handleDeleteCert maps to DELETE /open/cert/{id}
func handleDeleteCert(w http.ResponseWriter, r *http.Request) {
	trimmedPath := strings.TrimSuffix(r.URL.Path, "/")
	parts := strings.Split(trimmedPath, "/")
	idStr := parts[len(parts)-1]
	targetID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		log.Printf("Invalid cert ID in delete request: %s", idStr)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(CertResponse{Err: "bad_request", Msg: "Invalid certificate ID format"})
		return
	}

	log.Printf("Received delete request for certificate ID: %d", targetID)

	cacheMutex.Lock()
	var domainsToDelete []string
	for domain, cert := range certCache {
		if cert.ID == targetID {
			domainsToDelete = append(domainsToDelete, domain)
		}
	}

	for _, domain := range domainsToDelete {
		delete(certCache, domain)
	}
	cacheMutex.Unlock()

	if len(domainsToDelete) == 0 {
		json.NewEncoder(w).Encode(CertResponse{Data: "not_found", Err: "", Msg: "Certificate not found"})
		return
	}

	// Delete from disk
	primaryDomain := domainsToDelete[0]
	fileName := sanitizeDomainFilename(primaryDomain) + ".pem"
	filePath := filepath.Join(certDir, fileName)
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		log.Printf("Failed to delete cert file %s: %v", filePath, err)
	}

	// Delete backup .crt and .key files as well
	os.Remove(filepath.Join(certDir, sanitizeDomainFilename(primaryDomain)+".crt"))
	os.Remove(filepath.Join(certDir, sanitizeDomainFilename(primaryDomain)+".key"))

	// Sync with Caddy to reflect the deletion
	if err := syncWithCaddy(); err != nil {
		log.Printf("Failed to sync deletion with Caddy: %v", err)
	}

	log.Printf("Deleted certificate ID %d (%s)", targetID, strings.Join(domainsToDelete, ", "))
	json.NewEncoder(w).Encode(CertResponse{
		Data: "success",
		Err:  "",
		Msg:  "Certificate deleted successfully",
	})
}

// parsing and helper functions

func getCertID(crtPEM string) int64 {
	h := fnv.New64a()
	h.Write([]byte(crtPEM))
	return int64(h.Sum64() & 0x7FFFFFFFFFFFFFFF) // Positive 64-bit int
}

func parsePEMCert(crtPEM string) ([]string, time.Time, string, error) {
	block, _ := pem.Decode([]byte(crtPEM))
	if block == nil {
		return nil, time.Time{}, "", fmt.Errorf("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, time.Time{}, "", err
	}

	domainsMap := make(map[string]bool)
	if cert.Subject.CommonName != "" {
		domainsMap[cert.Subject.CommonName] = true
	}
	for _, san := range cert.DNSNames {
		domainsMap[san] = true
	}

	domains := make([]string, 0, len(domainsMap))
	for d := range domainsMap {
		domains = append(domains, d)
	}

	issuer := cert.Issuer.CommonName
	if issuer == "" && len(cert.Issuer.Organization) > 0 {
		issuer = cert.Issuer.Organization[0]
	}

	return domains, cert.NotAfter, issuer, nil
}

func sanitizeDomainFilename(domain string) string {
	s := strings.ReplaceAll(domain, "*", "_wildcard_")
	s = strings.ReplaceAll(s, "..", "_")
	return s
}

func saveCertToDisk(cert CaddyCert) error {
	if len(cert.Domains) == 0 {
		return fmt.Errorf("certificate has no domains")
	}
	primaryDomain := cert.Domains[0]
	baseName := sanitizeDomainFilename(primaryDomain)

	// Save combined .pem
	pemPath := filepath.Join(certDir, baseName+".pem")
	pemContent := fmt.Sprintf("%s\n%s", strings.TrimSpace(cert.Certificate), strings.TrimSpace(cert.Key))
	if err := os.WriteFile(pemPath, []byte(pemContent), 0600); err != nil {
		return err
	}

	// Also write separate .crt and .key files for easy debugging or other apps
	crtPath := filepath.Join(certDir, baseName+".crt")
	keyPath := filepath.Join(certDir, baseName+".key")
	_ = os.WriteFile(crtPath, []byte(cert.Certificate), 0644)
	_ = os.WriteFile(keyPath, []byte(cert.Key), 0600)

	return nil
}

func loadCertsFromDisk() error {
	files, err := os.ReadDir(certDir)
	if err != nil {
		return err
	}

	loadedCount := 0
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".pem") {
			continue
		}

		path := filepath.Join(certDir, file.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("Failed to read file %s: %v", path, err)
			continue
		}

		var certPEM, keyPEM string
		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				certPEM = string(pem.EncodeToMemory(block))
			} else if strings.Contains(block.Type, "KEY") {
				keyPEM = string(pem.EncodeToMemory(block))
			}
		}

		if certPEM == "" || keyPEM == "" {
			log.Printf("Skipping file %s: missing CERTIFICATE or PRIVATE KEY block", file.Name())
			continue
		}

		domains, notAfter, issuer, err := parsePEMCert(certPEM)
		if err != nil {
			log.Printf("Failed to parse cert from file %s: %v", file.Name(), err)
			continue
		}

		certID := getCertID(certPEM)
		caddyCert := CaddyCert{
			Certificate: certPEM,
			Key:         keyPEM,
			Domains:     domains,
			NotAfter:    notAfter,
			Issuer:      issuer,
			ID:          certID,
		}

		cacheMutex.Lock()
		for _, domain := range domains {
			certCache[domain] = caddyCert
		}
		cacheMutex.Unlock()
		loadedCount++
	}

	log.Printf("Loaded %d certificates from disk cache", loadedCount)
	return nil
}

// Caddy API synchronization functions

type CaddyLoadPemItem struct {
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
}

func startSyncLoop() {
	ticker := time.NewTicker(syncInterval)
	for range ticker.C {
		if err := syncWithCaddy(); err != nil {
			log.Printf("[SyncLoop] Error syncing with Caddy: %v", err)
		}
	}
}

func syncWithCaddy() error {
	cacheMutex.RLock()
	uniqueCertsMap := make(map[int64]CaddyCert)
	for _, cert := range certCache {
		uniqueCertsMap[cert.ID] = cert
	}
	cacheMutex.RUnlock()

	var payload []CaddyLoadPemItem
	for _, cert := range uniqueCertsMap {
		payload = append(payload, CaddyLoadPemItem{
			Certificate: cert.Certificate,
			Key:         cert.Key,
		})
	}

	if payload == nil {
		payload = []CaddyLoadPemItem{}
	}

	caddyPayload, getErr := getCaddyPEMCerts()
	if getErr == nil {
		if certListsMatch(payload, caddyPayload) {
			return nil
		}
		log.Printf("[Sync] Config drift or new certs detected. Syncing with Caddy...")
	} else {
		log.Printf("[Sync] Path load_pem is empty or Caddy is uninitialized: %v. Initializing...", getErr)
	}

	return initializeCaddyCerts(payload)
}

func certListsMatch(listA, listB []CaddyLoadPemItem) bool {
	if len(listA) != len(listB) {
		return false
	}
	mapB := make(map[string]bool)
	for _, item := range listB {
		mapB[normalizePEM(item.Certificate)] = true
	}
	for _, item := range listA {
		if !mapB[normalizePEM(item.Certificate)] {
			return false
		}
	}
	return true
}

func normalizePEM(pemStr string) string {
	s := strings.ReplaceAll(pemStr, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\t", "")
	return s
}

func getCaddyPEMCerts() ([]CaddyLoadPemItem, error) {
	resp, code, err := caddyRequest(http.MethodGet, "/config/apps/tls/certificates/load_pem", nil)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNotFound {
		return nil, fmt.Errorf("load_pem path not found (404)")
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", code, string(resp))
	}

	var items []CaddyLoadPemItem
	if err := json.Unmarshal(resp, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func initializeCaddyCerts(certs []CaddyLoadPemItem) error {
	_, code, err := caddyRequest(http.MethodPut, "/config/apps/tls/certificates/load_pem", certs)
	if err == nil && code == http.StatusOK {
		return nil
	}

	log.Printf("[CaddyAPI] Path /config/apps/tls/certificates/load_pem not writable (code %d). Trying parent...", code)
	_, code, err = caddyRequest(http.MethodPut, "/config/apps/tls/certificates", map[string]interface{}{
		"load_pem": certs,
	})
	if err == nil && code == http.StatusOK {
		return nil
	}

	log.Printf("[CaddyAPI] Path /config/apps/tls/certificates not writable (code %d). Trying parent...", code)
	_, code, err = caddyRequest(http.MethodPut, "/config/apps/tls", map[string]interface{}{
		"certificates": map[string]interface{}{
			"load_pem": certs,
		},
	})
	if err == nil && code == http.StatusOK {
		return nil
	}

	log.Printf("[CaddyAPI] Path /config/apps/tls not writable (code %d). Trying parent...", code)
	appsResp, appsCode, appsErr := caddyRequest(http.MethodGet, "/config/apps", nil)
	var appsMap map[string]interface{}
	if appsErr == nil && appsCode == http.StatusOK {
		_ = json.Unmarshal(appsResp, &appsMap)
	}
	if appsMap == nil {
		appsMap = make(map[string]interface{})
	}

	appsMap["tls"] = map[string]interface{}{
		"certificates": map[string]interface{}{
			"load_pem": certs,
		},
	}

	_, code, err = caddyRequest(http.MethodPut, "/config/apps", appsMap)
	if err == nil && code == http.StatusOK {
		return nil
	}

	return fmt.Errorf("failed to sync with Caddy, last API code: %d, error: %v", code, err)
}

func caddyRequest(method, path string, body interface{}) ([]byte, int, error) {
	url := fmt.Sprintf("%s%s", caddyURL, path)
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		bodyReader = strings.NewReader(string(b))
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return respBody, resp.StatusCode, err
	}

	return respBody, resp.StatusCode, nil
}
