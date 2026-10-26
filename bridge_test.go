package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	cert, key string
	leaf      []byte
	root      *x509.Certificate
}

func certificates(t *testing.T, serial int64) fixture {
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return k
	}
	rootKey, interKey, leafKey := key(), key(), key()
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	root, _ = x509.ParseCertificate(rootDER)
	inter := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	interDER, e := x509.CreateCertificate(rand.Reader, inter, root, &interKey.PublicKey, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	inter, _ = x509.ParseCertificate(interDER)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "bridge.test"}, DNSNames: []string{"bridge.test", "www.bridge.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, inter, &leafKey.PublicKey, interKey)
	if e != nil {
		t.Fatal(e)
	}
	k, e := x509.MarshalPKCS8PrivateKey(leafKey)
	if e != nil {
		t.Fatal(e)
	}
	return fixture{cert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})), key: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})), leaf: leafDER, root: root}
}

func setup(t *testing.T) {
	t.Helper()
	certDir = t.TempDir()
	token = "unit-test-only"
	replaceCache(map[string]CaddyCert{})
	oldURL, oldClient := caddyURL, httpClient
	t.Cleanup(func() { caddyURL = oldURL; httpClient = oldClient; replaceCache(map[string]CaddyCert{}) })
}

func request(t *testing.T, h http.Handler, method, path string, body interface{}, auth string) *httptest.ResponseRecorder {
	t.Helper()
	var b []byte
	if raw, ok := body.(string); ok {
		b = []byte(raw)
	} else if body != nil {
		var e error
		b, e = json.Marshal(body)
		if e != nil {
			t.Fatal(e)
		}
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	if auth != "" {
		r.Header.Set("X-SLCE-API-TOKEN", auth)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var result map[string]interface{}
	if e := json.Unmarshal(w.Body.Bytes(), &result); e != nil {
		t.Fatalf("non-JSON %s %s: status %d", method, path, w.Code)
	}
	if _, ok := result["msg"].(string); !ok {
		t.Fatal("AllinSSL requires msg string")
	}
	return w
}

func upload(f fixture) interface{} {
	return map[string]interface{}{"type": 2, "manual": map[string]string{"crt": f.cert, "key": f.key}}
}

func requireStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status=%d want=%d response=%s", w.Code, want, w.Body.String())
	}
}

// Conditional configuration fake rejects stale writes and preserves raw fields.
type fakeAdmin struct {
	mu               sync.Mutex
	root             map[string]interface{}
	revision, writes int
	reject, conflict bool
	methods          []string
}

func fakeCaddy(t *testing.T, root map[string]interface{}) *fakeAdmin {
	t.Helper()
	f := &fakeAdmin{root: root}
	s := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(s.Close)
	caddyURL = s.URL
	httpClient = s.Client()
	return f
}

func (f *fakeAdmin) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method == "GET" {
		w.Header().Set("ETag", fmt.Sprintf("\"/config/ rev%d\"", f.revision))
		json.NewEncoder(w).Encode(f.root)
		return
	}
	f.methods = append(f.methods, r.Method+" "+r.URL.Path)
	if f.reject {
		w.WriteHeader(400)
		io.WriteString(w, `{"error":"sensitive-private-key-must-not-be-echoed"}`)
		return
	}
	if f.conflict {
		f.conflict = false
		f.root["concurrent"] = true
		f.revision++
		w.WriteHeader(412)
		return
	}
	if r.Header.Get("If-Match") != fmt.Sprintf("\"/config/ rev%d\"", f.revision) {
		w.WriteHeader(412)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/config/"), "/")
	obj := f.root
	for _, part := range parts[:len(parts)-1] {
		var ok bool
		obj, ok = obj[part].(map[string]interface{})
		if !ok {
			w.WriteHeader(404)
			return
		}
	}
	k := parts[len(parts)-1]
	_, exists := obj[k]
	if (r.Method == "PUT" && exists) || (r.Method == "PATCH" && !exists) {
		w.WriteHeader(409)
		return
	}
	var v interface{}
	if json.NewDecoder(r.Body).Decode(&v) != nil {
		w.WriteHeader(400)
		return
	}
	obj[k] = v
	f.revision++
	f.writes++
}

func (f *fakeAdmin) entries() []interface{} {
	return f.root["apps"].(map[string]interface{})["tls"].(map[string]interface{})["certificates"].(map[string]interface{})["load_pem"].([]interface{})
}

func TestProtocolAuthenticationAndMethods(t *testing.T) {
	setup(t)
	fakeCaddy(t, map[string]interface{}{})
	h := newHandler()
	for _, p := range []string{"/api/open/site/group", "/api/open/system", "/api/open/cert"} {
		for _, tok := range []string{"", "wrong"} {
			requireStatus(t, request(t, h, "GET", p, nil, tok), 401)
		}
	}
	w := request(t, h, "GET", "/api/open/site/group", nil, token)
	requireStatus(t, w, 200)
	var res map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &res)
	if res["msg"] != "" || len(res["data"].([]interface{})) != 0 {
		t.Fatal("unexpected group response")
	}
	for _, p := range []string{"/api/open/site/group", "/api/open/system", "/api/open/cert"} {
		requireStatus(t, request(t, h, "PATCH", p, nil, token), 405)
	}
	for _, body := range []string{`{}`, `null`, `{"cert_id":0}`, `{"cert_id":-1}`, `{"cert_id":1.2}`, `{"cert_id":null}`, `{"cert_id":true}`, `{"cert_id":"123"}`, `{"cert_id":9223372036854775808}`, `{`, `{"cert_id":1} {}`} {
		requireStatus(t, request(t, h, "PUT", "/api/open/system", body, token), 400)
	}
	requireStatus(t, request(t, h, "PUT", "/api/open/system", `{"cert_id":123}`, token), 404)
}

func TestUploadBindRecoveryAndInvalidPair(t *testing.T) {
	setup(t)
	f := fakeCaddy(t, map[string]interface{}{})
	h := newHandler()
	chain := certificates(t, 3)
	// Migrate a legacy combined PEM, keeping every chain block and leaf metadata.
	if err := os.WriteFile(filepath.Join(certDir, "legacy.pem"), []byte(chain.cert+chain.key), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadCertsFromDisk(); err != nil {
		t.Fatal(err)
	}
	before := uniqueCerts(snapshotCache())
	if len(before) != 1 || before[0].Certificate != chain.cert || before[0].Issuer != "test intermediate" {
		t.Fatal("legacy chain or leaf metadata lost")
	}
	w := request(t, h, "POST", "/api/open/cert", upload(chain), token)
	requireStatus(t, w, 200)
	// Reproduce AllinSSL's map[string]any -> float64 -> JSON round trip.
	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	id := result["data"].(float64)
	if id <= 0 || id > float64(maxSafeID) || int64(id) != before[0].ID || result["msg"] != "" {
		t.Fatal("unsafe ID or nonempty success msg")
	}
	requireStatus(t, request(t, h, "PUT", "/api/open/system", map[string]interface{}{"cert_id": id}, token), 200)
	if len(f.entries()) != 1 {
		t.Fatal("certificate not applied")
	}
	disk, err := os.ReadFile(filepath.Join(certDir, snapshotName))
	if err != nil {
		t.Fatal(err)
	}
	other := certificates(t, 4)
	invalid := chain
	invalid.key = other.key
	requireStatus(t, request(t, h, "POST", "/api/open/cert", upload(invalid), token), 400)
	after, _ := os.ReadFile(filepath.Join(certDir, snapshotName))
	if !bytes.Equal(disk, after) || !reflect.DeepEqual(before[0].Certificate, uniqueCerts(snapshotCache())[0].Certificate) {
		t.Fatal("invalid upload changed cache")
	}
	replaceCache(map[string]CaddyCert{})
	if err := loadCertsFromDisk(); err != nil {
		t.Fatal(err)
	}
	recovered := uniqueCerts(snapshotCache())
	if len(recovered) != 1 || recovered[0].Certificate != chain.cert || recovered[0].ID != int64(id) {
		t.Fatal("restart changed chain or ID")
	}
	requireStatus(t, request(t, h, "PUT", "/api/open/system", map[string]interface{}{"cert_id": float64(oldCertID(chain.cert))}, token), 200)
	// Renewal retires every domain alias and authoritative disk state survives reload.
	requireStatus(t, request(t, h, "POST", "/api/open/cert", upload(other), token), 200)
	if err := loadCertsFromDisk(); err != nil {
		t.Fatal(err)
	}
	if cs := uniqueCerts(snapshotCache()); len(cs) != 1 || cs[0].Certificate != other.cert {
		t.Fatal("renewal resurrected legacy cache")
	}
	requireStatus(t, request(t, h, "DELETE", fmt.Sprintf("/api/open/cert/%d", getCertID(other.cert)), nil, token), 200)
	if err := loadCertsFromDisk(); err != nil {
		t.Fatal(err)
	}
	if len(snapshotCache()) != 0 || len(f.entries()) != 0 {
		t.Fatal("deletion resurrected legacy cache")
	}
}

func TestCaddyCreateUpdatePreserveConflictAndFailure(t *testing.T) {
	for _, depth := range []int{0, 1, 2, 3, 4} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			setup(t)
			root := map[string]interface{}{"other": "preserve"}
			obj := root
			for i, k := range []string{"apps", "tls", "certificates", "load_pem"} {
				if i >= depth {
					break
				}
				if k == "load_pem" {
					obj[k] = []interface{}{}
				} else {
					child := map[string]interface{}{"untouched": "preserve"}
					obj[k] = child
					obj = child
				}
			}
			f := fakeCaddy(t, root)
			f.conflict = true
			h := newHandler()
			a, b := certificates(t, 3), certificates(t, 4)
			requireStatus(t, request(t, h, "POST", "/api/open/cert", upload(a), token), 200)
			if root["other"] != "preserve" || root["concurrent"] != true {
				t.Fatal("concurrent config lost")
			}
			// Unrelated entry, loader and automation must survive updates and deletion.
			tlsObj := root["apps"].(map[string]interface{})["tls"].(map[string]interface{})
			tlsObj["automation"] = map[string]interface{}{"keep": true}
			certObj := tlsObj["certificates"].(map[string]interface{})
			certObj["load_files"] = []interface{}{"keep"}
			foreign := map[string]interface{}{"certificate": "unmanaged", "key": "unmanaged-key", "tags": []interface{}{"foreign"}, "custom": "preserve"}
			certObj["load_pem"] = append(f.entries(), foreign)
			requireStatus(t, request(t, h, "POST", "/api/open/cert", upload(b), token), 200)
			if len(f.entries()) != 2 || !reflect.DeepEqual(f.entries()[0], foreign) || tlsObj["automation"] == nil || certObj["load_files"] == nil {
				t.Fatal("unrelated config lost")
			}
			if !strings.HasPrefix(f.methods[len(f.methods)-1], "PATCH ") {
				t.Fatal("existing list not patched")
			}
			f.reject = true
			w := request(t, h, "PUT", "/api/open/system", map[string]interface{}{"cert_id": getCertID(b.cert)}, token)
			// Force drift so binding actually attempts a write and surfaces failure.
			if w.Code != 200 {
				t.Fatalf("identical config should require no write: %d", w.Code)
			}
			certObj["load_pem"] = []interface{}{foreign}
			w = request(t, h, "PUT", "/api/open/system", map[string]interface{}{"cert_id": getCertID(b.cert)}, token)
			requireStatus(t, w, 502)
			if strings.Contains(w.Body.String(), "sensitive-private") || !strings.Contains(w.Body.String(), "HTTP 400") {
				t.Fatal("unsafe or unhelpful Caddy error")
			}
			requireStatus(t, request(t, h, "POST", "/api/open/cert", upload(a), token), 502)
			if uniqueCerts(snapshotCache())[0].ID != getCertID(a.cert) {
				t.Fatal("failed sync lost durable desired state")
			}
			f.reject = false
			requireStatus(t, request(t, h, "PUT", "/api/open/system", map[string]interface{}{"cert_id": getCertID(a.cert)}, token), 200)
		})
	}
}

func TestPEMValidationAndIDCollision(t *testing.T) {
	setup(t)
	a, b := certificates(t, 3), certificates(t, 4)
	parts := strings.SplitAfter(a.cert, "-----END CERTIFICATE-----\n")
	for _, pair := range [][2]string{{a.cert, b.key}, {parts[1] + parts[0], a.key}, {a.cert + "garbage", a.key}, {a.cert, a.key + a.key}, {"", a.key}, {a.cert, ""}} {
		if _, e := parsePair(pair[0], pair[1]); e == nil {
			t.Fatal("invalid PEM pair accepted")
		}
	}
	canonical, e := parsePair(strings.ReplaceAll(a.cert, "\n", "\r\n"), a.key)
	if e != nil || canonical.ID != getCertID(a.cert) {
		t.Fatal("ID not canonical")
	}
	c, _ := parsePair(b.cert, b.key)
	c.ID = getCertID(a.cert)
	replaceCache(map[string]CaddyCert{"collision.test": c})
	requireStatus(t, request(t, newHandler(), "POST", "/api/open/cert", upload(a), token), 409)
	if _, err := os.Stat(filepath.Join(certDir, snapshotName)); !os.IsNotExist(err) {
		t.Fatal("collision wrote cache")
	}
}

func unusedAddress(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

func TestRealCaddyTLS(t *testing.T) {
	bin := os.Getenv("CADDY_BIN")
	if bin == "" {
		t.Skip("set CADDY_BIN to run real Caddy TLS integration")
	}
	setup(t)
	admin, https := unusedAddress(t), unusedAddress(t)
	conf := map[string]interface{}{"admin": map[string]interface{}{"listen": admin}, "apps": map[string]interface{}{"http": map[string]interface{}{"servers": map[string]interface{}{"test": map[string]interface{}{"listen": []string{https}, "automatic_https": map[string]interface{}{"disable": true}, "tls_connection_policies": []interface{}{map[string]interface{}{}}, "routes": []interface{}{map[string]interface{}{"handle": []interface{}{map[string]interface{}{"handler": "static_response", "body": "preserved route"}}}}}}}, "tls": map[string]interface{}{"certificates": map[string]interface{}{"load_pem": []interface{}{}, "load_files": []interface{}{}}, "automation": map[string]interface{}{"policies": []interface{}{map[string]interface{}{"subjects": []string{"unused.test"}, "issuers": []interface{}{map[string]interface{}{"module": "internal"}}}}}}}}
	// Test PKI must never attempt to modify the machine's trust store.
	conf["apps"].(map[string]interface{})["pki"] = map[string]interface{}{
		"certificate_authorities": map[string]interface{}{
			"local": map[string]interface{}{"install_trust": false},
		},
	}
	file := filepath.Join(t.TempDir(), "caddy.json")
	data, _ := json.Marshal(conf)
	if e := os.WriteFile(file, data, 0600); e != nil {
		t.Fatal(e)
	}
	logFile, e := os.Create(filepath.Join(t.TempDir(), "caddy.log"))
	if e != nil {
		t.Fatal(e)
	}
	defer logFile.Close()
	cmd := exec.Command(bin, "run", "--config", file)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	caddyURL = "http://" + admin
	// /load replaces Caddy's Admin server and asynchronously closes its old
	// connections. Do not reuse an idle connection for the next non-idempotent
	// fixture POST: net/http cannot safely retry that request after a reset.
	transport := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	httpClient = &http.Client{Timeout: 3 * time.Second, Transport: transport}
	ready := false
	for i := 0; i < 100; i++ {
		_, s, _, err := caddyCall("GET", "/config/", nil, "")
		if err == nil && s == 200 {
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("real Caddy not ready; inspect local test log")
	}
	h := newHandler()
	a, b := certificates(t, 3), certificates(t, 4)
	// Exercise real Caddy creation at every missing ancestor, not only a fake.
	for _, apps := range []interface{}{nil, map[string]interface{}{}, map[string]interface{}{"tls": map[string]interface{}{}}, map[string]interface{}{"tls": map[string]interface{}{"certificates": map[string]interface{}{}}}} {
		minimal := map[string]interface{}{"admin": map[string]interface{}{"listen": admin}}
		if apps != nil {
			minimal["apps"] = apps
		}
		_, status, _, err := caddyCall("POST", "/load", minimal, "")
		if err != nil || status != 200 {
			t.Fatalf("cannot load initialization fixture: HTTP %d, error %v", status, err)
		}
		requireStatus(t, request(t, h, "POST", "/api/open/cert", upload(a), token), 200)
	}
	if _, status, _, err := caddyCall("POST", "/load", conf, ""); err != nil || status != 200 {
		t.Fatal("cannot restore TLS integration fixture")
	}
	verify := func(f fixture) {
		t.Helper()
		roots := x509.NewCertPool()
		roots.AddCert(f.root)
		conn, e := tls.Dial("tcp", https, &tls.Config{RootCAs: roots, ServerName: "bridge.test"})
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Close()
		state := conn.ConnectionState()
		if len(state.PeerCertificates) != 2 || !bytes.Equal(state.PeerCertificates[0].Raw, f.leaf) {
			t.Fatal("TLS returned wrong leaf or incomplete chain")
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "bridge.test"}}}
		defer client.CloseIdleConnections()
		res, e := client.Get("https://" + https)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		if string(body) != "preserved route" {
			t.Fatal("HTTP route lost")
		}
	}
	for _, chain := range []fixture{a, b} {
		requireStatus(t, request(t, h, "POST", "/api/open/cert", upload(chain), token), 200)
		requireStatus(t, request(t, h, "PUT", "/api/open/system", map[string]interface{}{"cert_id": float64(getCertID(chain.cert))}, token), 200)
		verify(chain)
	}
	replaceCache(map[string]CaddyCert{})
	if e := loadCertsFromDisk(); e != nil {
		t.Fatal(e)
	}
	if e := syncWithCaddy(); e != nil {
		t.Fatal(e)
	}
	verify(b)
	data, s, _, e := caddyCall("GET", "/config/", nil, "")
	if e != nil || s != 200 {
		t.Fatal("cannot inspect final Caddy config")
	}
	var final map[string]interface{}
	json.Unmarshal(data, &final)
	tlsObj := final["apps"].(map[string]interface{})["tls"].(map[string]interface{})
	if tlsObj["automation"] == nil || tlsObj["certificates"].(map[string]interface{})["load_files"] == nil {
		t.Fatal("unrelated TLS configuration lost")
	}
}

func TestPersistenceAndCorruptRecovery(t *testing.T) {
	setup(t)
	fakeCaddy(t, map[string]interface{}{})
	h := newHandler()
	a, b := certificates(t, 3), certificates(t, 4)
	requireStatus(t, request(t, h, "POST", "/api/open/cert", upload(a), token), 200)
	before := snapshotCache()
	originalDir := certDir
	// A path beneath a regular file deterministically fails even when run as root.
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if e := os.WriteFile(blocker, []byte("x"), 0600); e != nil {
		t.Fatal(e)
	}
	certDir = filepath.Join(blocker, "cache")
	requireStatus(t, request(t, h, "POST", "/api/open/cert", upload(b), token), 500)
	if !reflect.DeepEqual(before, snapshotCache()) {
		t.Fatal("disk failure changed live desired cache")
	}
	certDir = originalDir
	if e := os.WriteFile(filepath.Join(certDir, snapshotName), []byte(`[{"certificate":"invalid","key":"invalid"}]`), 0600); e != nil {
		t.Fatal(e)
	}
	if e := loadCertsFromDisk(); e == nil {
		t.Fatal("corrupt authoritative cache accepted")
	}
	if !reflect.DeepEqual(before, snapshotCache()) {
		t.Fatal("failed reload destroyed live cache")
	}
}

func TestAmbiguousLegacyID(t *testing.T) {
	setup(t)
	f1, f2 := certificates(t, 3), certificates(t, 4)
	c1, _ := parsePair(f1.cert, f1.key)
	c2, _ := parsePair(f2.cert, f2.key)
	c1.LegacyIDs = []int64{1 << 60}
	c2.LegacyIDs = []int64{1<<60 + 1}
	replaceCache(map[string]CaddyCert{"a": c1, "b": c2})
	if _, ok := findCert(1 << 60); ok {
		t.Fatal("ambiguous rounded legacy ID matched")
	}
}
