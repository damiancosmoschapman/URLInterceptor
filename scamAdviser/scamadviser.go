package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery" // HTML parsing
)

func main() {
	// Example URL to check
	urlToCheck := "http://malware.testing.google.test/testing/malware/"

	// Check URL
	result, err := CheckURL(urlToCheck)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// Print results
	if result.IsMalicious {
		fmt.Printf("🚨 MALICIOUS: %s\n", urlToCheck)
		fmt.Printf("Threat Type: %s\n", result.ThreatType)
	} else {
		fmt.Printf("✅ SAFE: %s\n", urlToCheck)
	}
}

// Result represents the check result
type Result struct {
	URL         string
	IsMalicious bool
	ThreatType  string
}

// CheckURL submits a URL to cyberskills.ie and parses the response
func CheckURL(urlToCheck string) (*Result, error) {
	// Configure HTTP client
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Prepare form data
	formData := url.Values{}
	formData.Set("url", urlToCheck) // Field name might need adjustment

	// Submit POST request
	resp, err := client.PostForm("https://check.cyberskills.ie/", formData)
	if err != nil {
		return nil, fmt.Errorf("failed to submit URL: %v", err)
	}
	defer resp.Body.Close()

	// Parse HTML response
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %v", err)
	}

	// Extract result - ADAPT THESE SELECTORS BASED ON ACTUAL PAGE STRUCTURE
	result := &Result{URL: urlToCheck}

	// Look for danger/warning messages (inspect actual page to find correct selectors)
	doc.Find(".alert-danger, .warning-message, .threat-indicator").Each(func(i int, s *goquery.Selection) {
		text := strings.ToLower(s.Text())
		if strings.Contains(text, "malicious") || strings.Contains(text, "danger") {
			result.IsMalicious = true
			result.ThreatType = "Generic Threat" // Extract specific type if available
		}
	})

	// Alternative: Check for safe/clean indicators
	if !result.IsMalicious {
		doc.Find(".alert-success, .safe-indicator").Each(func(i int, s *goquery.Selection) {
			if strings.Contains(strings.ToLower(s.Text()), "safe") {
				result.IsMalicious = false
			}
		})
	}

	return result, nil
}
