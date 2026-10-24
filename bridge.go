package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Serializes mutations, disk snapshots and synchronization; cacheMutex protects readers.
var operationMutex sync.Mutex

const maxSafeID int64 = 1<<53 - 1
const managedTag = "acbridge"
const snapshotName = ".acbridge-cache.json"

func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHome)
	for _, p := range []string{"/open/cert", "/open/cert/", "/api/open/cert", "/api/open/cert/"} {
		mux.HandleFunc(p, authMiddleware(handleCert))
	}
	mux.HandleFunc("/api/open/site/group", authMiddleware(handleSiteGroups))
	mux.HandleFunc("/api/open/system", authMiddleware(handleSystem))
	return mux
}

func reply(w http.ResponseWriter, status int, data interface{}, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(CertResponse{Data: data, Err: code, Msg: message})
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	reply(w, 405, nil, "method_not_allowed", "Method not allowed")
	return false
}

func decodeRequest(w http.ResponseWriter, r *http.Request, v interface{}) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON request")
	}
	var extra interface{}
	if d.Decode(&extra) != io.EOF {
		return fmt.Errorf("expected one JSON object")
	}
	return nil
}

func handleSiteGroups(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	// AllinSSL 1.1.4 SafeLineAPITest checks msg only; no site groups are managed.
	reply(w, 200, []interface{}{}, "", "")
}

func parseID(n json.Number) (int64, error) {
	if len(n) > 32 {
		return 0, fmt.Errorf("cert_id must be a positive integer")
	}
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil || f <= 0 || f > float64(uint64(1)<<63) {
		return 0, fmt.Errorf("cert_id must be a positive integer")
	}
	x, ok := new(big.Rat).SetString(string(n))
	if !ok || !x.IsInt() || !x.Num().IsInt64() || x.Sign() <= 0 {
		return 0, fmt.Errorf("cert_id must be a positive integer")
	}
	return x.Num().Int64(), nil
}

func findCert(id int64) (CaddyCert, bool) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	matches := map[int64]CaddyCert{}
	for _, c := range certCache {
		match := c.ID == id
		for _, old := range c.LegacyIDs {
			if old == id || (old > maxSafeID && float64(old) == float64(id)) {
				match = true
			}
		}
		if match {
			matches[c.ID] = c
		}
	}
	if len(matches) != 1 {
		return CaddyCert{}, false
	}
	for _, c := range matches {
		return c, true
	}
	return CaddyCert{}, false
}

func handleSystem(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPut) {
		return
	}
	var req struct {
		CertID json.RawMessage `json:"cert_id"`
	}
	if err := decodeRequest(w, r, &req); err != nil {
		reply(w, 400, nil, "bad_request", err.Error())
		return
	}
	id, err := parseID(json.Number(req.CertID))
	if err != nil {
		reply(w, 400, nil, "bad_request", err.Error())
		return
	}
	operationMutex.Lock()
	defer operationMutex.Unlock()
	c, ok := findCert(id)
	if !ok {
		reply(w, 404, nil, "not_found", "Certificate not found or ambiguous legacy ID")
		return
	}
	if err := syncWithCaddyLocked(); err != nil {
		reply(w, 502, nil, "caddy_sync_failed", err.Error())
		return
	}
	reply(w, 200, map[string]interface{}{"cert_id": c.ID}, "", "")
}

func oldCertID(s string) int64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return int64(h.Sum64() & 0x7fffffffffffffff)
}

func getCertID(s string) int64 {
	h := sha256.Sum256([]byte(s))
	id := int64(binary.BigEndian.Uint64(h[:8]) >> 11)
	if id == 0 {
		return 1
	}
	return id
}

// Canonical PEM ensures IDs and the full chain survive combined-PEM disk recovery.
func parsePair(certText, keyText string) (CaddyCert, error) {
	var certPEM, keyPEM []byte
	rest := []byte(certText)
	for len(bytes.TrimSpace(rest)) > 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(rest), []byte("-----BEGIN ")) {
			return CaddyCert{}, fmt.Errorf("invalid certificate PEM")
		}
		b, next := pem.Decode(rest)
		if b == nil || b.Type != "CERTIFICATE" {
			return CaddyCert{}, fmt.Errorf("expected CERTIFICATE PEM blocks")
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return CaddyCert{}, fmt.Errorf("invalid certificate DER")
		}
		certPEM = append(certPEM, pem.EncodeToMemory(b)...)
		rest = next
	}
	if !bytes.HasPrefix(bytes.TrimSpace([]byte(keyText)), []byte("-----BEGIN ")) {
		return CaddyCert{}, fmt.Errorf("invalid private key PEM")
	}
	b, rest := pem.Decode([]byte(keyText))
	if b == nil || len(bytes.TrimSpace(rest)) != 0 {
		return CaddyCert{}, fmt.Errorf("expected one private key PEM block")
	}
	switch b.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
	default:
		return CaddyCert{}, fmt.Errorf("unsupported private key PEM type")
	}
	keyPEM = pem.EncodeToMemory(b)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return CaddyCert{}, fmt.Errorf("invalid certificate/private key pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return CaddyCert{}, fmt.Errorf("invalid leaf certificate")
	}
	for i := 1; i < len(pair.Certificate); i++ {
		parent, e := x509.ParseCertificate(pair.Certificate[i])
		child, _ := x509.ParseCertificate(pair.Certificate[i-1])
		if e != nil || child.CheckSignatureFrom(parent) != nil {
			return CaddyCert{}, fmt.Errorf("certificate chain must be ordered leaf first with valid issuer signatures")
		}
	}
	domains := append([]string{}, leaf.DNSNames...)
	if leaf.Subject.CommonName != "" {
		domains = append(domains, leaf.Subject.CommonName)
	}
	sort.Strings(domains)
	unique := domains[:0]
	for _, d := range domains {
		if len(unique) == 0 || unique[len(unique)-1] != d {
			unique = append(unique, d)
		}
	}
	if len(unique) == 0 {
		return CaddyCert{}, fmt.Errorf("certificate has no DNS names")
	}
	issuer := leaf.Issuer.CommonName
	if issuer == "" && len(leaf.Issuer.Organization) > 0 {
		issuer = leaf.Issuer.Organization[0]
	}
	c := CaddyCert{Certificate: string(certPEM), Key: string(keyPEM), Domains: unique, NotAfter: leaf.NotAfter, Issuer: issuer, ID: getCertID(string(certPEM))}
	c.LegacyIDs = []int64{oldCertID(certText), oldCertID(c.Certificate)}
	return c, nil
}

func snapshotCache() map[string]CaddyCert {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	m := map[string]CaddyCert{}
	for k, v := range certCache {
		m[k] = v
	}
	return m
}

func uniqueCerts(m map[string]CaddyCert) []CaddyCert {
	byID := map[int64]CaddyCert{}
	for _, c := range m {
		byID[c.ID] = c
	}
	out := make([]CaddyCert, 0, len(byID))
	for _, c := range byID {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func persistCache(m map[string]CaddyCert) error {
	// A single atomic authoritative snapshot avoids mixed chain/key files and
	// resurrected legacy domain files after renewal or deletion.
	data, err := json.Marshal(uniqueCerts(m))
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(certDir, ".cache-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(certDir, snapshotName))
}

func replaceCache(m map[string]CaddyCert) { cacheMutex.Lock(); certCache = m; cacheMutex.Unlock() }

func handleUpsertCert(w http.ResponseWriter, r *http.Request) {
	var req UpsertCertRequest
	if err := decodeRequest(w, r, &req); err != nil {
		reply(w, 400, nil, "bad_request", err.Error())
		return
	}
	c, err := parsePair(req.Manual.Crt, req.Manual.Key)
	if err != nil {
		reply(w, 400, nil, "invalid_cert", err.Error())
		return
	}
	operationMutex.Lock()
	defer operationMutex.Unlock()
	next := snapshotCache()
	for _, existing := range uniqueCerts(next) {
		if existing.ID == c.ID && existing.Certificate == c.Certificate {
			seen := map[int64]bool{}
			aliases := []int64{}
			for _, id := range append(c.LegacyIDs, existing.LegacyIDs...) {
				if !seen[id] {
					seen[id] = true
					aliases = append(aliases, id)
				}
			}
			c.LegacyIDs = aliases
		}
		if existing.ID == c.ID && existing.Certificate != c.Certificate {
			reply(w, 409, nil, "id_collision", "Certificate ID collision; existing cache preserved")
			return
		}
	}
	// IDs are content derived. Existing request id is only an update hint; reject
	// unknown hints rather than pretending a different certificate was updated.
	if req.ID != 0 {
		if _, ok := findCert(req.ID); !ok {
			reply(w, 404, nil, "not_found", "Update certificate ID not found")
			return
		}
	}
	retired := map[int64]bool{}
	for _, domain := range c.Domains {
		if old, ok := next[domain]; ok {
			retired[old.ID] = true
		}
	}
	for d, old := range next {
		if retired[old.ID] {
			delete(next, d)
		}
	}
	for _, d := range c.Domains {
		next[d] = c
	}
	if err := persistCache(next); err != nil {
		reply(w, 500, nil, "cache_failed", "Failed to persist certificate cache")
		return
	}
	replaceCache(next)
	// Valid desired state is durable even if Caddy rejects it. Caller gets failure;
	// the sync loop, binding call or repeated POST retries the same stable ID.
	if err := syncWithCaddyLocked(); err != nil {
		reply(w, 502, nil, "caddy_sync_failed", err.Error())
		return
	}
	reply(w, 200, c.ID, "", "")
}

func handleDeleteCert(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	id, err := parseID(json.Number(parts[len(parts)-1]))
	if err != nil {
		reply(w, 400, nil, "bad_request", err.Error())
		return
	}
	operationMutex.Lock()
	defer operationMutex.Unlock()
	c, ok := findCert(id)
	if !ok {
		reply(w, 404, nil, "not_found", "Certificate not found")
		return
	}
	next := snapshotCache()
	for d, v := range next {
		if v.ID == c.ID {
			delete(next, d)
		}
	}
	if err := persistCache(next); err != nil {
		reply(w, 500, nil, "cache_failed", "Failed to persist certificate cache")
		return
	}
	replaceCache(next)
	if err := syncWithCaddyLocked(); err != nil {
		reply(w, 502, nil, "caddy_sync_failed", err.Error())
		return
	}
	reply(w, 200, nil, "", "")
}

func loadCertsFromDisk() error {
	operationMutex.Lock()
	defer operationMutex.Unlock()
	m := map[string]CaddyCert{}
	add := func(c CaddyCert) error {
		for _, old := range m {
			if old.ID == c.ID && old.Certificate != c.Certificate {
				return fmt.Errorf("certificate ID collision in disk cache")
			}
		}
		for _, d := range c.Domains {
			m[d] = c
		}
		return nil
	}
	data, err := os.ReadFile(filepath.Join(certDir, snapshotName))
	if err == nil {
		var saved []CaddyCert
		if json.Unmarshal(data, &saved) != nil {
			return fmt.Errorf("invalid cache snapshot")
		}
		for _, s := range saved {
			c, e := parsePair(s.Certificate, s.Key)
			if e != nil {
				return fmt.Errorf("invalid certificate in cache snapshot: %w", e)
			}
			c.LegacyIDs = append(c.LegacyIDs, s.LegacyIDs...)
			if e = add(c); e != nil {
				return e
			}
		}
	} else if os.IsNotExist(err) {
		files, e := os.ReadDir(certDir)
		if e != nil {
			return e
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".pem") {
				continue
			}
			data, e := os.ReadFile(filepath.Join(certDir, f.Name()))
			if e != nil {
				return e
			}
			var certText, keyText string
			rest := data
			for len(bytes.TrimSpace(rest)) > 0 {
				b, next := pem.Decode(rest)
				if b == nil {
					return fmt.Errorf("invalid legacy PEM cache")
				}
				rest = next
				switch b.Type {
				case "CERTIFICATE":
					certText += string(pem.EncodeToMemory(b))
				case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
					if keyText != "" {
						return fmt.Errorf("multiple private keys in legacy cache")
					}
					keyText = string(pem.EncodeToMemory(b))
				default:
					return fmt.Errorf("unsupported legacy PEM block")
				}
			}
			c, e := parsePair(certText, keyText)
			if e != nil {
				return fmt.Errorf("invalid legacy cache certificate: %w", e)
			}
			if e = add(c); e != nil {
				return e
			}
		}
	} else {
		return err
	}
	replaceCache(m)
	log.Printf("Loaded %d certificates from disk cache", len(uniqueCerts(m)))
	return nil
}

type CaddyLoadPemItem struct {
	Certificate string   `json:"certificate"`
	Key         string   `json:"key"`
	Tags        []string `json:"tags,omitempty"`
}

func startSyncLoop() {
	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()
	for range ticker.C {
		if err := syncWithCaddy(); err != nil {
			log.Printf("[SyncLoop] %v", err)
		}
	}
}

func syncWithCaddy() error {
	operationMutex.Lock()
	defer operationMutex.Unlock()
	return syncWithCaddyLocked()
}

func syncWithCaddyLocked() error {
	desired := []CaddyLoadPemItem{}
	for _, c := range uniqueCerts(snapshotCache()) {
		desired = append(desired, CaddyLoadPemItem{Certificate: c.Certificate, Key: c.Key, Tags: []string{managedTag}})
	}
	return initializeCaddyCerts(desired)
}

func caddyCall(method, path string, body interface{}, etag string) ([]byte, int, string, error) {
	var reader io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return nil, 0, "", fmt.Errorf("cannot encode Caddy configuration")
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimRight(caddyURL, "/")+path, reader)
	if err != nil {
		return nil, 0, "", fmt.Errorf("invalid Caddy Admin URL")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if etag != "" {
		req.Header.Set("If-Match", etag)
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, "", fmt.Errorf("Caddy Admin %s %s: transport failure", method, path)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return nil, res.StatusCode, "", fmt.Errorf("cannot read Caddy response")
	}
	return b, res.StatusCode, res.Header.Get("ETag"), nil
}

// Do not echo Caddy response bodies: validation errors can include private keys.
func caddyStatus(method, path string, status int) error {
	return fmt.Errorf("Caddy Admin %s %s returned HTTP %d (%s); inspect Caddy diagnostics without sharing credentials", method, path, status, http.StatusText(status))
}

func initializeCaddyCerts(desired []CaddyLoadPemItem) error {
	for attempt := 0; attempt < 4; attempt++ {
		data, status, etag, err := caddyCall("GET", "/config/", nil, "")
		if err != nil {
			return err
		}
		if status != 200 {
			return caddyStatus("GET", "/config/", status)
		}
		if etag == "" {
			return fmt.Errorf("Caddy Admin did not provide ETag; refusing unsafe update")
		}
		var root map[string]json.RawMessage
		if json.Unmarshal(data, &root) != nil {
			return fmt.Errorf("invalid Caddy configuration response")
		}
		if root == nil {
			root = map[string]json.RawMessage{}
		}
		// Find the deepest existing object. PUT creates a missing key; PATCH replaces
		// an existing load_pem list. The root ETag guards even ancestor changes.
		keys := []string{"apps", "tls", "certificates", "load_pem"}
		obj := root
		missing := -1
		for i, k := range keys {
			raw, exists := obj[k]
			if !exists {
				missing = i
				break
			}
			if i == len(keys)-1 {
				break
			}
			var child map[string]json.RawMessage
			if json.Unmarshal(raw, &child) != nil || child == nil {
				return fmt.Errorf("Caddy %s must be an object", k)
			}
			obj = child
		}
		var existing []map[string]json.RawMessage
		if missing < 0 {
			if json.Unmarshal(obj["load_pem"], &existing) != nil {
				return fmt.Errorf("invalid Caddy load_pem configuration")
			}
		}
		merged := make([]map[string]json.RawMessage, 0, len(existing)+len(desired))
		for _, entry := range existing {
			var tags []string
			json.Unmarshal(entry["tags"], &tags)
			owned := false
			for _, t := range tags {
				if t == managedTag {
					owned = true
				}
			}
			// Adopt an identical legacy cached certificate; unrelated untagged entries
			// and their additional properties remain intact.
			var cert string
			json.Unmarshal(entry["certificate"], &cert)
			for _, c := range desired {
				if len(tags) == 0 && cert == c.Certificate {
					owned = true
				}
			}
			if !owned {
				merged = append(merged, entry)
			}
		}
		for _, c := range desired {
			b, _ := json.Marshal(c)
			var entry map[string]json.RawMessage
			json.Unmarshal(b, &entry)
			merged = append(merged, entry)
		}
		if missing < 0 && reflect.DeepEqual(existing, merged) {
			return nil
		}
		method, path := "PATCH", "/config/apps/tls/certificates/load_pem"
		var payload interface{} = merged
		if missing >= 0 {
			method = "PUT"
			path = "/config/" + strings.Join(keys[:missing+1], "/")
			for i := len(keys) - 1; i > missing; i-- {
				payload = map[string]interface{}{keys[i]: payload}
			}
		}
		_, status, _, err = caddyCall(method, path, payload, etag)
		if err != nil {
			return err
		}
		if status == 412 || status == 409 {
			continue
		}
		if status != 200 {
			return caddyStatus(method, path, status)
		}
		return nil
	}
	return fmt.Errorf("Caddy configuration changed concurrently; conditional update failed after 4 attempts")
}
