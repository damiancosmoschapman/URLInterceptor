package protocolHandler

import (
	"UrlInterceptor/virusTotal"
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// VirusTotal API configuration
const (
	vtAPIKey = ""
	vtAPIURL = "https://www.virustotal.com/api/v3/urls"

	// Toggle this to disable VirusTotal checks during testing
	enableVirusTotalChecks = true

	// CA certificate files
	caCertFile = "proxy-ca.crt"
	caKeyFile  = "proxy-ca.key"
)

// VirusTotal response structures
type VirusTotalResponse struct {
	Data struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"data"`
}

type ScanReportResponse struct {
	Data struct {
		Attributes struct {
			Stats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
			} `json:"stats"`
			Results map[string]struct {
				Category string `json:"category"`
				Result   string `json:"result"`
			} `json:"results"`
		} `json:"attributes"`
	} `json:"data"`
}

var trustedDomains = map[string]bool{
	"www.gstatic.com":       true,
	"fonts.gstatic.com":     true,
	"ssl.gstatic.com":       true,
	"www.googleapis.com":    true,
	"fonts.googleapis.com":  true,
	"mail.google.com":       true,
	"accounts.google.com":   true,
	"google.com":            true,
	"www.google.com":        true,
	"gstatic.com":           true,
	"googleapis.com":        true,
	"googleusercontent.com": true,
}

// Cache for storing URL check results
type URLCache struct {
	mu      sync.RWMutex
	results map[string]*URLCheckResult
}

type URLCheckResult struct {
	IsSafe    bool
	CheckedAt time.Time
	Details   string
}

var urlCache = &URLCache{
	results: make(map[string]*URLCheckResult),
}

// Certificate cache for generated certificates
type CertCache struct {
	mu    sync.RWMutex
	certs map[string]*tls.Certificate
}

var certCache = &CertCache{
	certs: make(map[string]*tls.Certificate),
}

// CA certificate and key
var (
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
)

// MITMProxy handles HTTPS interception
type MITMProxy struct {
	transport *http.Transport
}

func NewMITMProxy() *MITMProxy {
	return &MITMProxy{
		transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// Initialize or load CA certificate
func initCA() error {
	// Check if CA files exist
	if _, err := os.Stat(caCertFile); err == nil {
		// Load existing CA
		//log.Println("Loading existing CA certificate...")
		return loadCA()
	}

	// Generate new CA
	log.Println("Generating new CA certificate...")
	return generateCA()
}

// Generate a new CA certificate
func generateCA() error {
	// Generate RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"URL Safety Proxy"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour * 10), // 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Generate certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %v", err)
	}

	// Save certificate
	certOut, err := os.Create(caCertFile)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %v", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return fmt.Errorf("failed to write certificate: %v", err)
	}

	// Save key
	keyOut, err := os.Create(caKeyFile)
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}
	defer keyOut.Close()

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("failed to write key: %v", err)
	}

	// Set global variables
	caCert, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %v", err)
	}
	caKey = key

	log.Printf("CA certificate created: %s", caCertFile)
	log.Println("IMPORTANT: Install this certificate in your browser as a trusted root CA")

	return nil
}

// Load existing CA certificate
func loadCA() error {
	// Load certificate
	certPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to parse CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Load key
	keyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read CA key: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to parse CA key PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA key: %v", err)
	}

	caCert = cert
	caKey = key

	return nil
}

// Generate a certificate for a specific domain
func generateCert(domain string) (*tls.Certificate, error) {
	// Check cache first
	certCache.mu.RLock()
	if cert, ok := certCache.certs[domain]; ok {
		certCache.mu.RUnlock()
		return cert, nil
	}
	certCache.mu.RUnlock()

	// Generate new certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{"URL Safety Proxy"},
			CommonName:   domain,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{domain, "*." + domain},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
	}

	// Cache the certificate
	certCache.mu.Lock()
	certCache.certs[domain] = cert
	certCache.mu.Unlock()

	return cert, nil
}

// Handle CONNECT requests for HTTPS interception with enhanced Google redirect detection
func (p *MITMProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	log.Printf("!!! CONNECT request received for: %s", r.Host)

	// Extract hostname
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	// Special handling for Google domains
	isGoogleDomain := strings.Contains(host, "google.com") || strings.Contains(host, "googleapis.com")
	if isGoogleDomain {
		log.Printf("!!! >>> GOOGLE DOMAIN CONNECT: %s <<<", host)
		log.Printf("!!! This is where we should intercept Gmail redirects!")
	}

	// Generate certificate for this domain
	cert, err := generateCert(host)
	if err != nil {
		log.Printf("Failed to generate certificate for %s: %v", host, err)
		http.Error(w, "Certificate generation failed", http.StatusInternalServerError)
		return
	}

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Send 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Wrap client connection with TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	// Read the actual HTTPS request
	reader := bufio.NewReader(tlsConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("Failed to read HTTPS request: %v", err)
		return
	}

	// Set the proper URL scheme and host
	req.URL.Scheme = "https"
	req.URL.Host = r.Host
	req.RequestURI = ""

	// Log full request details for Google domains
	if isGoogleDomain {
		log.Printf("Google domain request - Method: %s, URL: %s, Path: %s, Query: %s",
			req.Method, req.URL.String(), req.URL.Path, req.URL.RawQuery)
	}

	// Handle the request
	p.handleHTTPSRequest(tlsConn, req)
}

// Check if a URL/path should skip VirusTotal checking
func shouldSkipVirusTotalCheck(urlStr string) bool {
	// Parse the URL
	u, err := url.Parse(urlStr)
	if err != nil {
		// If it's not a valid URL, check if it's a path
		if strings.HasPrefix(urlStr, "/") {
			// Common Google connectivity/tracking endpoints
			skipPaths := []string{
				"/generate_204",
				"/gen_204",
				"/blank.html",
				"/favicon.ico",
				"/robots.txt",
				"/_/chrome/newtab",
			}
			for _, path := range skipPaths {
				if urlStr == path {
					return true
				}
			}
		}
		return false
	}

	// Check if it's a trusted domain
	if isTrustedDomain(u.Host) {
		return true
	}

	return false
}

// Handle the actual HTTPS request with enhanced Google redirect detection
func (p *MITMProxy) handleHTTPSRequest(clientConn *tls.Conn, req *http.Request) {
	fullURL := req.URL.String()
	if !strings.HasPrefix(fullURL, "http") {
		fullURL = fmt.Sprintf("https://%s%s", req.Host, req.URL.Path)
		if req.URL.RawQuery != "" {
			fullURL += "?" + req.URL.RawQuery
		}
	}

	log.Printf("HTTPS request: %s %s (Host: %s)", req.Method, fullURL, req.Host)

	// Enhanced Google redirect detection
	if (strings.Contains(req.Host, "google.com") && strings.Contains(req.URL.Path, "/url")) ||
		(strings.Contains(fullURL, "google.com/url")) {
		log.Printf("Potential Google redirect URL detected: %s", fullURL)

		// Try to extract the actual URL
		actualURL := extractGoogleRedirectURL(fullURL)
		if actualURL != "" {
			log.Printf("Google redirect detected, actual URL: %s", actualURL)

			// Check the actual URL with VirusTotal
			if enableVirusTotalChecks {
				isSafe, details := checkURLSafety(actualURL)
				if !isSafe {
					// Send warning page
					sendWarningPage(clientConn, actualURL, details)
					return
				}
			}

			// Send redirect response
			sendRedirect(clientConn, actualURL)
			return
		} else {
			log.Printf("Could not extract URL from Google redirect: %s", fullURL)
		}
	}

	// Detect common redirect patterns
	detectRedirectPatterns(req)

	// Check if URL should be scanned
	if enableVirusTotalChecks && !shouldSkipVirusTotalCheck(fullURL) {
		isSafe, details := checkURLSafety(fullURL)
		if !isSafe {
			sendWarningPage(clientConn, fullURL, details)
			return
		}
	}

	// Forward the request to the actual server
	resp, err := p.transport.RoundTrip(req)
	if err != nil {
		log.Printf("Failed to forward request: %v", err)
		sendError(clientConn, http.StatusBadGateway, "Failed to forward request")
		return
	}
	defer resp.Body.Close()

	// Send response back to client
	if err := resp.Write(clientConn); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

// Handle HTTP requests with enhanced redirect detection
func (p *MITMProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("HTTP request: %s %s", r.Method, r.URL.String())

	// Build the full URL if needed
	fullURL := r.URL.String()
	if !strings.HasPrefix(fullURL, "http") {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		fullURL = fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)
		if r.URL.RawQuery != "" {
			fullURL += "?" + r.URL.RawQuery
		}
	}

	// Log more details for debugging
	log.Printf("Request details - Method: %s, Host: %s, Path: %s, Full URL: %s",
		r.Method, r.Host, r.URL.Path, fullURL)

	// Special logging for potential Gmail redirect destinations
	if r.Host == "example.com" || strings.Contains(r.Host, "example.com") {
		log.Printf("!!! GMAIL REDIRECT DESTINATION DETECTED: %s", fullURL)
		log.Printf("!!! This is the final URL from the Gmail link click")
	}

	// Check referer header to see if coming from Google
	referer := r.Header.Get("Referer")
	if strings.Contains(referer, "google.com/url") {
		log.Printf("!!! Request came from Google redirect! Referer: %s", referer)
		log.Printf("!!! Final destination URL: %s", fullURL)

		// Extract the original Google redirect URL from referer if possible
		if u, err := url.Parse(referer); err == nil {
			if q := u.Query().Get("q"); q != "" {
				log.Printf("!!! Original Gmail link target was: %s", q)
			}
		}
	}

	// Detect common redirect patterns
	detectRedirectPatterns(r)

	// Check if URL should be scanned
	if enableVirusTotalChecks && !shouldSkipVirusTotalCheck(fullURL) {
		isSafe, details := checkURLSafety(fullURL)
		if !isSafe {
			showWarningPage(w, fullURL, details)
			return
		}
	}

	// FIX: Ensure the request URL has the scheme and host
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	// Clear the RequestURI to prevent issues
	r.RequestURI = ""

	// Remove proxy-related headers
	r.Header.Del("Proxy-Connection")

	// Log what we're about to forward
	log.Printf("Forwarding request to: %s", r.URL.String())

	// Forward the request
	resp, err := p.transport.RoundTrip(r)
	if err != nil {
		log.Printf("ERROR forwarding request: %v", err)
		// Provide more specific error message
		errorMsg := fmt.Sprintf("Failed to forward request to %s: %v", r.URL.String(), err)
		http.Error(w, errorMsg, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy body
	copied, err := io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Error copying response body: %v", err)
	} else {
		log.Printf("Successfully forwarded response: %d bytes", copied)
	}
}

// Extract actual URL from Google redirect with enhanced parameter handling
func extractGoogleRedirectURL(googleURL string) string {
	log.Printf("Attempting to extract URL from: %s", googleURL)

	u, err := url.Parse(googleURL)
	if err != nil {
		log.Printf("Failed to parse Google URL: %v", err)
		return ""
	}

	// Try 'q' parameter first (most common)
	q := u.Query().Get("q")
	if q != "" {
		log.Printf("Found 'q' parameter: %s", q)
		if _, err := url.Parse(q); err == nil {
			return q
		}
	}

	// Try 'url' parameter
	urlParam := u.Query().Get("url")
	if urlParam != "" {
		log.Printf("Found 'url' parameter: %s", urlParam)
		if _, err := url.Parse(urlParam); err == nil {
			return urlParam
		}
	}

	// Try 'continue' parameter (sometimes used)
	cont := u.Query().Get("continue")
	if cont != "" {
		log.Printf("Found 'continue' parameter: %s", cont)
		if _, err := url.Parse(cont); err == nil {
			return cont
		}
	}

	log.Printf("No valid URL found in Google redirect")
	return ""
}

// Detect common redirect patterns to identify potential Gmail click destinations
func detectRedirectPatterns(r *http.Request) {
	// Check various headers that might indicate a redirect
	headers := []string{"Referer", "Origin", "X-Forwarded-For"}
	for _, header := range headers {
		if value := r.Header.Get(header); value != "" && strings.Contains(value, "google.com") {
			log.Printf("!!! Redirect pattern detected - %s: %s", header, value)
		}
	}

	// Check if this might be a common redirect destination
	commonRedirectTargets := []string{
		"example.com", "bit.ly", "tinyurl.com", "ow.ly", "t.co",
		"goo.gl", "short.link", "rebrand.ly", "clickmeter.com",
	}

	for _, target := range commonRedirectTargets {
		if strings.Contains(r.Host, target) {
			log.Printf("!!! Common redirect target detected: %s", r.Host)
			log.Printf("!!! This might be the final destination of a Gmail link")
		}
	}
}

// Check if domain is trusted
func isTrustedDomain(host string) bool {
	// Remove port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return trustedDomains[host]
}

// Check URL safety with VirusTotal
func checkURLSafety(targetURL string) (bool, string) {
	// Validate URL first
	u, err := url.Parse(targetURL)
	if err != nil {
		log.Printf("Invalid URL format: %s", targetURL)
		return true, "Invalid URL format"
	}

	// Make sure it has a scheme and host
	if u.Scheme == "" || u.Host == "" {
		log.Printf("URL missing scheme or host: %s", targetURL)
		return true, "Incomplete URL"
	}

	// Check cache first
	urlCache.mu.RLock()
	if result, exists := urlCache.results[targetURL]; exists {
		if time.Since(result.CheckedAt) < time.Hour {
			urlCache.mu.RUnlock()
			return result.IsSafe, result.Details
		}
	}
	urlCache.mu.RUnlock()

	log.Printf("Checking URL with VirusTotal: %s", targetURL)

	// Submit URL to VirusTotal
	scanID, err := virusTotal.SubmitURLForScanning(vtAPIKey, targetURL)
	if err != nil {
		log.Printf("Error submitting URL to VirusTotal: %v", err)
		// Don't block on VirusTotal errors
		return true, fmt.Sprintf("VirusTotal check failed: %v", err)
	}

	// Wait for scan
	time.Sleep(2 * time.Second)

	// Get results
	report, err := virusTotal.GetScanReport(vtAPIKey, scanID)
	if err != nil {
		log.Printf("Error getting scan report: %v", err)
		return true, fmt.Sprintf("VirusTotal report retrieval failed: %v", err)
	}

	// Interpret results
	stats := report.Data.Attributes.Stats
	totalDetections := stats.Malicious + stats.Suspicious

	isSafe := totalDetections <= 2
	details := fmt.Sprintf("Scanned by %d engines: %d malicious, %d suspicious, %d harmless",
		stats.Malicious+stats.Suspicious+stats.Harmless+stats.Undetected,
		stats.Malicious, stats.Suspicious, stats.Harmless)

	// Cache result
	urlCache.mu.Lock()
	urlCache.results[targetURL] = &URLCheckResult{
		IsSafe:    isSafe,
		CheckedAt: time.Now(),
		Details:   details,
	}
	urlCache.mu.Unlock()

	return isSafe, details
}

// Send redirect response
func sendRedirect(conn net.Conn, location string) {
	response := fmt.Sprintf("HTTP/1.1 302 Found\r\n"+
		"Location: %s\r\n"+
		"Content-Length: 0\r\n"+
		"\r\n", location)
	conn.Write([]byte(response))
}

// Send error response
func sendError(conn net.Conn, statusCode int, message string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\n"+
		"Content-Type: text/plain\r\n"+
		"Content-Length: %d\r\n"+
		"\r\n%s", statusCode, http.StatusText(statusCode), len(message), message)
	conn.Write([]byte(response))
}

// Send warning page for HTTPS connections
func sendWarningPage(conn net.Conn, targetURL, details string) {
	html := generateWarningHTML(targetURL, details)
	response := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
		"Content-Type: text/html; charset=utf-8\r\n"+
		"Content-Length: %d\r\n"+
		"\r\n%s", len(html), html)
	conn.Write([]byte(response))
}

// Show warning page for HTTP connections
func showWarningPage(w http.ResponseWriter, targetURL, details string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, generateWarningHTML(targetURL, details))
}

// Generate warning HTML
func generateWarningHTML(targetURL, details string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Security Warning</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 20px;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .warning-container {
            background-color: white;
            border: 2px solid #dc3545;
            border-radius: 8px;
            padding: 30px;
            max-width: 600px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        h1 {
            color: #dc3545;
            margin-top: 0;
        }
        .url {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            word-break: break-all;
            margin: 20px 0;
        }
        .details {
            color: #666;
            margin: 20px 0;
        }
        .actions {
            margin-top: 30px;
        }
        button {
            padding: 10px 20px;
            margin: 0 10px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        .btn-safe {
            background-color: #28a745;
            color: white;
        }
        .btn-proceed {
            background-color: #ffc107;
            color: #333;
        }
    </style>
</head>
<body>
    <div class="warning-container">
        <h1>⚠️ Security Warning</h1>
        <p>The URL you are trying to access has been flagged as potentially malicious.</p>
        <div class="url">%s</div>
        <div class="details">%s</div>
        <div class="actions">
            <button class="btn-safe" onclick="window.history.back()">Go Back to Safety</button>
            <button class="btn-proceed" onclick="if(confirm('Are you sure you want to proceed? This may harm your computer.')) { window.location.href='%s' }">Proceed Anyway (Not Recommended)</button>
        </div>
    </div>
</body>
</html>
`, targetURL, details, targetURL)
}

func StartTransparentProxy() {
	// Initialize CA certificate
	if err := initCA(); err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	// Create proxy
	proxy := NewMITMProxy()

	// HTTP handler with enhanced debug logging
	httpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle test endpoint INSIDE the main handler
		if r.URL.Path == "/test" && r.Method != "CONNECT" {
			fmt.Fprintf(w, "Proxy is working! You reached the test endpoint.")
			return
		}

		// Log EVERY request that hits the proxy
		log.Printf("===== INCOMING REQUEST =====")
		log.Printf("Method: %s", r.Method)
		log.Printf("URL: %s", r.URL.String())
		log.Printf("Host: %s", r.Host)
		log.Printf("RequestURI: %s", r.RequestURI)

		if r.Method == "CONNECT" {
			log.Printf(">>> CONNECT REQUEST DETECTED for host: %s", r.Host)
			proxy.handleConnect(w, r)
			// Don't log "END REQUEST" for CONNECT as the connection stays open
			return
		} else {
			log.Printf(">>> Regular HTTP request")
			proxy.handleHTTP(w, r)
		}
		log.Printf("===== END REQUEST =====\n")
	})

	// Create servers WITHOUT mux - use handler directly!
	httpServer := &http.Server{
		Addr:         ":65080",
		Handler:      httpHandler, // Direct handler, no mux!
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	httpsServer := &http.Server{
		Addr:         ":65443",
		Handler:      httpHandler, // Same handler, no mux!
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start servers
	go func() {
		log.Println("Starting HTTP proxy on :65080")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	go func() {
		log.Println("Starting HTTPS proxy on :65443")
		if err := httpsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS server error: %v", err)
		}
	}()

	// Print instructions
	printInstructions()

	// Wait for interrupt
	<-sigChan

	log.Println("\nShutting down proxy...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		httpServer.Shutdown(ctx)
	}()

	go func() {
		defer wg.Done()
		httpsServer.Shutdown(ctx)
	}()

	wg.Wait()
	log.Println("Proxy stopped")
}

func printInstructions() {
	//cwd, _ := os.Getwd()
	//log.Println("=================================================")
	//log.Println("MITM URL Safety Proxy is running!")
	//log.Println("=================================================")
	//log.Println("HTTP proxy: http://localhost:65080")
	//log.Println("HTTPS proxy: https://localhost:65443")
	//log.Println("")
	//log.Println("Test endpoint: http://localhost:65080/test")
	//log.Println("")
	//log.Println("IMPORTANT SETUP STEPS:")
	//log.Println("1. Install the CA certificate in your browser:")
	//log.Printf("   - Certificate location: %s", filepath.Join(cwd, caCertFile))
	//log.Println("   - Chrome: Settings → Privacy → Security → Manage certificates → Import")
	//log.Println("   - Firefox: Settings → Privacy → View Certificates → Import")
	//log.Println("")
	//log.Println("2. Configure your nftables rules (already done)")
	//log.Println("")
	//log.Println("3. Set your VirusTotal API key in the code")
	//log.Println("")
	//if enableVirusTotalChecks {
	//	log.Println("VirusTotal integration: ENABLED")
	//	if vtAPIKey == "YOUR_VIRUSTOTAL_API_KEY" {
	//		log.Println("WARNING: Please set your VirusTotal API key!")
	//	}
	//} else {
	//	log.Println("VirusTotal integration: DISABLED")
	//}
	//log.Println("")
	//log.Println("The proxy will now intercept HTTPS traffic including Gmail redirects!")
	log.Println("Press Ctrl+C to stop")
	log.Println("=================================================")
}
