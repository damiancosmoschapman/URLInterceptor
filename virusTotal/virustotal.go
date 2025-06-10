package virusTotal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

const (
	virusTotalURL = "https://www.virustotal.com/api/v3/urls"
)

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

func main() {
	apiKey := os.Getenv("VIRUSTOTAL_API_KEY")
	if apiKey == "" {
		fmt.Println("VIRUSTOTAL_API_KEY is not set")
		return
	}

	// URL to scan
	urlToScan := "http://example.com" // Replace with the URL you want to scan

	// Step 1: Submit the URL for scanning
	scanID, err := SubmitURLForScanning(apiKey, urlToScan)
	if err != nil {
		fmt.Println("Error submitting URL for scanning:", err)
		return
	}

	fmt.Println("Scan ID:", scanID)

	// Step 2: Retrieve the scan report
	report, err := GetScanReport(apiKey, scanID)
	if err != nil {
		fmt.Println("Error retrieving scan report:", err)
		return
	}

	// Step 3: Interpret the scan report
	interpretScanReport(report)
}

func SubmitURLForScanning(apiKey, urlToScan string) (string, error) {
	formData := url.Values{}
	formData.Set("url", urlToScan)

	req, err := http.NewRequest("POST", virusTotalURL, bytes.NewBufferString(formData.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status: %s, response: %s", resp.Status, string(body))
	}

	var result VirusTotalResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", err
	}

	return result.Data.ID, nil
}

func GetScanReport(apiKey, scanID string) (*ScanReportResponse, error) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/analyses/%s", scanID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-apikey", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %s, response: %s", resp.Status, string(body))
	}

	var report ScanReportResponse
	err = json.Unmarshal(body, &report)
	if err != nil {
		return nil, err
	}

	return &report, nil
}

func interpretScanReport(report *ScanReportResponse) {
	stats := report.Data.Attributes.Stats
	results := report.Data.Attributes.Results

	fmt.Println("Scan Report Summary:")
	fmt.Printf("Harmless: %d\n", stats.Harmless)
	fmt.Printf("Malicious: %d\n", stats.Malicious)
	fmt.Printf("Suspicious: %d\n", stats.Suspicious)
	fmt.Printf("Undetected: %d\n", stats.Undetected)

	if stats.Malicious > 0 {
		fmt.Println("The URL is MALICIOUS.")
	} else if stats.Suspicious > 0 {
		fmt.Println("The URL is SUSPICIOUS.")
	} else {
		fmt.Println("The URL is SAFE.")
	}

	fmt.Println("\nDetailed Results:")
	for engine, result := range results {
		fmt.Printf("%s: %s (%s)\n", engine, result.Result, result.Category)
	}
}
