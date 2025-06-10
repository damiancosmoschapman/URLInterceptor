package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

const (
	apiKey  = "AIzaSyBzPcqIdd1gNOd6zdJr7Hcfz0PBlIEi0-k" // <-- Replace this
	baseURL = "https://webrisk.googleapis.com/v1/uris:search"
)

type ThreatMatch struct {
	ThreatTypes []string `json:"threatTypes"`
}

type APIResponse struct {
	Threat *ThreatMatch `json:"threat"`
}

func checkURLV5(urlToCheck string) (bool, error) {
	// Build the URL with query parameters
	params := url.Values{}
	params.Add("uri", urlToCheck)
	params.Add("threatTypes", "MALWARE")
	params.Add("threatTypes", "SOCIAL_ENGINEERING")
	params.Add("key", apiKey)

	fullURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

	resp, err := http.Get(fullURL)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return false, fmt.Errorf("non-200 response: %d - %s", resp.StatusCode, string(bodyBytes))
	}

	var apiResp APIResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return false, err
	}

	// If Threat is non-nil, the URL is malicious
	if apiResp.Threat != nil {
		return true, nil
	}

	return false, nil
}

func main() {
	urlToCheck := "http://malware.testing.google.test/testing/malware/" // <-- A real malicious URL, NOT the test URL

	isMalicious, err := checkURLV5(urlToCheck)
	if err != nil {
		fmt.Println("Error checking URL:", err)
		os.Exit(1)
	}

	if isMalicious {
		fmt.Println("⚠️ The URL is flagged as malicious!")
	} else {
		fmt.Println("✅ The URL is safe.")
	}
}
