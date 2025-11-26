package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"
)

type apiError struct {
	Error string `json:"error"`
}

// ttsRequest represents a text-to-speech request body.
type ttsRequest struct {
	Text      string  `json:"text"`
	VoiceName string  `json:"voiceName"`
	VoiceLang string  `json:"voiceLang"`
	Rate      float64 `json:"rate"`
	Pitch     float64 `json:"pitch"`
}

func judge0ExecuteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req judge0Request
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid json"})
		return
	}
	base := os.Getenv("JUDGE0_URL")
	if base == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "Judge0 not configured"})
		return
	}
	body, _ := json.Marshal(req)
	url := strings.TrimRight(base, "/") + "/submissions?base64_encoded=false&wait=true"
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "request error"})
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if k := os.Getenv("JUDGE0_KEY"); k != "" {
		httpReq.Header.Set("X-RapidAPI-Key", k)
	}
	if h := os.Getenv("JUDGE0_HOST"); h != "" {
		httpReq.Header.Set("X-RapidAPI-Host", h)
	}
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiError{Error: "judge0 unreachable"})
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func bcryptHashHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req bcryptHashRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid json"})
		return
	}
	cost := req.Cost
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	h, err := bcrypt.GenerateFromPassword([]byte(req.Password), cost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "hash error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hash": string(h), "cost": cost})
}

func bcryptCompareHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req bcryptCompareRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid json"})
		return
	}
	err := bcrypt.CompareHashAndPassword([]byte(req.Hash), []byte(req.Password))
	writeJSON(w, http.StatusOK, map[string]bool{"match": err == nil})
}

type hashRequest struct {
	Algorithm string `json:"algorithm"`
	Input     string `json:"input"`
	Output    string `json:"output"`
}

type hmacRequest struct {
	Algorithm string `json:"algorithm"`
	Key       string `json:"key"`
	Input     string `json:"input"`
	Output    string `json:"output"`
}

type aesEncryptRequest struct {
	Key            string `json:"keyBase64"`
	Nonce          string `json:"nonceBase64"`
	Plaintext      string `json:"plaintext"`
	AssociatedData string `json:"aad"`
}

type aesDecryptRequest struct {
	Key            string `json:"keyBase64"`
	Nonce          string `json:"nonceBase64"`
	Ciphertext     string `json:"ciphertextBase64"`
	AssociatedData string `json:"aad"`
}

type rsaKeygenRequest struct {
	Bits int `json:"bits"`
}

type certDecodeRequest struct {
	PEM string `json:"pem"`
}

type bcryptHashRequest struct {
	Password string `json:"password"`
	Cost     int    `json:"cost"`
}

type bcryptCompareRequest struct {
	Password string `json:"password"`
	Hash     string `json:"hash"`
}

type judge0Request struct {
	LanguageID int    `json:"language_id"`
	SourceCode string `json:"source_code"`
	Stdin      string `json:"stdin"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func hashHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req hashRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid json"})
		return
	}
	var digest []byte
	switch strings.ToLower(req.Algorithm) {
	case "md5":
		// md5 intentionally not implemented for security reasons
		writeJSON(w, http.StatusBadRequest, apiError{Error: "md5 not supported"})
		return
	case "sha1":
		h := sha1.Sum([]byte(req.Input))
		digest = h[:]
	case "sha256":
		h := sha256.Sum256([]byte(req.Input))
		digest = h[:]
	case "sha512":
		h := sha512.Sum512([]byte(req.Input))
		digest = h[:]
	default:
		writeJSON(w, http.StatusBadRequest, apiError{Error: "unsupported algorithm"})
		return
	}
	out := strings.ToLower(req.Output)
	if out == "base64" {
		writeJSON(w, http.StatusOK, map[string]string{"digest": base64.StdEncoding.EncodeToString(digest)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"digest": hex.EncodeToString(digest)})
}

func hmacHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req hmacRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid json"})
		return
	}
	var mac hashFunc
	switch strings.ToLower(req.Algorithm) {
	case "sha1":
		mac = func(key []byte) hash { return hmac.New(sha1.New, key) }
	case "sha224":
		mac = func(key []byte) hash { return hmac.New(sha256.New224, key) }
	case "sha256":
		mac = func(key []byte) hash { return hmac.New(sha256.New, key) }
	case "sha3-256":
		mac = func(key []byte) hash { return hmac.New(sha3.New256, key) }
	case "sha384":
		mac = func(key []byte) hash { return hmac.New(sha512.New384, key) }
	case "sha3-384":
		mac = func(key []byte) hash { return hmac.New(sha3.New384, key) }
	case "sha512":
		mac = func(key []byte) hash { return hmac.New(sha512.New, key) }
	case "sha3-512":
		mac = func(key []byte) hash { return hmac.New(sha3.New512, key) }
	default:
		writeJSON(w, http.StatusBadRequest, apiError{Error: "unsupported algorithm"})
		return
	}
	h := mac([]byte(req.Key))
	io.WriteString(h, req.Input)
	s := h.Sum(nil)
	if strings.ToLower(req.Output) == "base64" {
		writeJSON(w, http.StatusOK, map[string]string{"hmac": base64.StdEncoding.EncodeToString(s)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"hmac": hex.EncodeToString(s)})
}

type hash interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

type hashFunc func(key []byte) hash

func aesEncryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req aesEncryptRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid json"})
		return
	}
	key, err := base64.StdEncoding.DecodeString(req.Key)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid key"})
		return
	}
	var nonce []byte
	if req.Nonce != "" {
		nonce, err = base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid nonce"})
			return
		}
	} else {
		nonce = make([]byte, 12)
		_, _ = rand.Read(nonce)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid key size"})
		return
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "gcm error"})
		return
	}
	var aad []byte
	if req.AssociatedData != "" {
		aad = []byte(req.AssociatedData)
	}
	ct := g.Seal(nil, nonce, []byte(req.Plaintext), aad)
	writeJSON(w, http.StatusOK, map[string]string{"ciphertextBase64": base64.StdEncoding.EncodeToString(ct), "nonceBase64": base64.StdEncoding.EncodeToString(nonce)})
}

func aesDecryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req aesDecryptRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid json"})
		return
	}
	key, err := base64.StdEncoding.DecodeString(req.Key)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid key"})
		return
	}
	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid nonce"})
		return
	}
	ct, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid ciphertext"})
		return
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid key size"})
		return
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "gcm error"})
		return
	}
	var aad []byte
	if req.AssociatedData != "" {
		aad = []byte(req.AssociatedData)
	}
	pt, err := g.Open(nil, nonce, ct, aad)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "decryption failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"plaintext": string(pt)})
}

func rsaKeygenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req rsaKeygenRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid json"})
		return
	}
	bits := req.Bits
	if bits == 0 {
		bits = 2048
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "keygen failed"})
		return
	}
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	pubBytes := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes})
	writeJSON(w, http.StatusOK, map[string]string{"privateKeyPEM": string(privPEM), "publicKeyPEM": string(pubPEM)})
}

func certDecodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req certDecodeRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid json"})
		return
	}
	p, _ := pem.Decode([]byte(req.PEM))
	if p == nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid pem"})
		return
	}
	switch p.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "parse error"})
			return
		}
		res := map[string]any{
			"subject":      cert.Subject.String(),
			"issuer":       cert.Issuer.String(),
			"notBefore":    cert.NotBefore.Format(time.RFC3339),
			"notAfter":     cert.NotAfter.Format(time.RFC3339),
			"dnsNames":     cert.DNSNames,
			"emails":       cert.EmailAddresses,
			"serialNumber": cert.SerialNumber.String(),
		}
		writeJSON(w, http.StatusOK, res)
		return
	case "CERTIFICATE REQUEST":
		csr, err := x509.ParseCertificateRequest(p.Bytes)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "parse error"})
			return
		}
		res := map[string]any{
			"subject":  csr.Subject.String(),
			"dnsNames": csr.DNSNames,
			"emails":   csr.EmailAddresses,
		}
		writeJSON(w, http.StatusOK, res)
		return
	default:
		writeJSON(w, http.StatusBadRequest, apiError{Error: "unsupported pem type"})
		return
	}
}

// ttsHandler proxies text-to-speech requests to an external TTS service
// configured via the TTS_URL environment variable. It expects JSON
// {"text":"...","voiceName":"...","voiceLang":"...","rate":1,"pitch":1}
// and streams back the audio bytes returned by the upstream service.
func ttsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	base := os.Getenv("TTS_URL")
	if base == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "TTS not configured"})
		return
	}
	var reqBody ttsRequest
	if err := readJSON(r, &reqBody); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid json"})
		return
	}
	if strings.TrimSpace(reqBody.Text) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "text is required"})
		return
	}
	body, _ := json.Marshal(reqBody)
	outReq, err := http.NewRequest(http.MethodPost, base, bytes.NewReader(body))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "tts request error"})
		return
	}
	outReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(outReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiError{Error: "tts unreachable"})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}
	// Proxy audio bytes through, preserving content type when possible.
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "audio/mpeg"
	}
	w.Header().Set("Content-Type", ct)
	// Suggest a filename so browsers treat it as downloadable.
	w.Header().Set("Content-Disposition", "attachment; filename=tts-audio")
	w.WriteHeader(http.StatusOK)
	io.Copy(w, resp.Body)
}

func withJSON(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		next.ServeHTTP(w, r)
	}
}

// iconsHandler handles requests to list available SVG icons
func iconsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	iconDir := filepath.Join("web", "assets", "SVG icons")
	matches, err := filepath.Glob(filepath.Join(iconDir, "*.svg"))
	if err != nil {
		http.Error(w, "Error reading icons directory", http.StatusInternalServerError)
		return
	}

	// Convert full paths to relative paths from the assets directory
	icons := make([]string, 0, len(matches))
	for _, match := range matches {
		// Convert to forward slashes for web compatibility
		relPath, err := filepath.Rel(filepath.Join("web", "assets"), match)
		if err != nil {
			continue
		}
		icons = append(icons, filepath.ToSlash(relPath))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"icons": icons,
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/hash", withJSON(hashHandler))
	mux.HandleFunc("/api/hmac", withJSON(hmacHandler))
	mux.HandleFunc("/api/aes/encrypt", withJSON(aesEncryptHandler))
	mux.HandleFunc("/api/aes/decrypt", withJSON(aesDecryptHandler))
	mux.HandleFunc("/api/rsa/keygen", withJSON(rsaKeygenHandler))
	mux.HandleFunc("/api/cert/decode", withJSON(certDecodeHandler))
	mux.HandleFunc("/api/bcrypt/hash", withJSON(bcryptHashHandler))
	mux.HandleFunc("/api/bcrypt/compare", withJSON(bcryptCompareHandler))
	mux.HandleFunc("/api/judge0/execute", withJSON(judge0ExecuteHandler))
	mux.HandleFunc("/api/icons", withJSON(iconsHandler))
	mux.HandleFunc("/api/tts", withJSON(ttsHandler))
	// Serve app.js with no-cache to ensure fresh JS across all pages
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, max-age=0, must-revalidate")
		http.ServeFile(w, r, filepath.Join("web", "app.js"))
	})
	fs := http.FileServer(http.Dir("web"))
	mux.Handle("/", spaHandler("web", fs))
	port := os.Getenv("PORT")
	if port == "" {
		port = os.Getenv("DEVTOOLS_PORT")
	}
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	log.Println("DevTools listening on", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func spaHandler(root string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if up, err := url.PathUnescape(p); err == nil {
			p = up
		}
		if p == "/" {
			next.ServeHTTP(w, r)
			return
		}
		rel := strings.TrimPrefix(p, "/")
		full := filepath.Join(root, filepath.FromSlash(filepath.Clean(rel)))
		if st, err := os.Stat(full); err == nil && !st.IsDir() {
			// Pass through to file server but ensure URL path is unescaped so http.FileServer can resolve it
			r2 := new(http.Request)
			*r2 = *r
			u := new(url.URL)
			*u = *r.URL
			u.Path = p
			r2.URL = u
			next.ServeHTTP(w, r2)
			return
		}
		http.ServeFile(w, r, filepath.Join(root, "index.html"))
	})
}
