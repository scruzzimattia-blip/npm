package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	lapiURL := os.Getenv("CROWDSEC_LAPI_URL")
	if lapiURL == "" {
		lapiURL = "http://traefik-stats-crowdsec:8080"
	}
	lapiKey := os.Getenv("CROWDSEC_LAPI_KEY")
	redirectURL := os.Getenv("REDIRECT_URL")
	if redirectURL == "" {
		redirectURL = "https://blocked.scruzzi.com"
	}

	fmt.Println("Starting Updated CrowdSec Bouncer on :8080")
	fmt.Printf("LAPI URL: %s\n", lapiURL)
	fmt.Printf("Redirect URL: %s\n", redirectURL)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Priority: X-Forwarded-For, X-Real-IP, RemoteAddr
		clientIP := ""
		
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the first IP in the list
			ips := strings.Split(xff, ",")
			clientIP = strings.TrimSpace(ips[0])
		}

		if clientIP == "" {
			clientIP = r.Header.Get("X-Real-IP")
		}

		if clientIP == "" {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err == nil {
				clientIP = host
			} else {
				clientIP = r.RemoteAddr
			}
		}

		// fmt.Printf("Checking IP: %s\n", clientIP)

		url := fmt.Sprintf("%s/v1/decisions?ip=%s", lapiURL, clientIP)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("X-Api-Key", lapiKey)

		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error querying LAPI: %v\n", err)
			w.Header().Set("X-Crowdsec-Decision", "none")
			w.WriteHeader(http.StatusOK)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			// If body is not empty [], it's a block
			if len(body) > 4 { 
				fmt.Printf("Blocking IP: %s\n", clientIP)
				
				// Try to extract reason from JSON
				reason := "Security Policy Violation"
				// Simple string searching to avoid complex JSON parsing for performance
				// Typical JSON: "reason":"crowdsecurity/http-path-traversal-probing"
				reasonIdx := strings.Index(string(body), "\"reason\":\"")
				if reasonIdx != -1 {
					start := reasonIdx + 10
					end := strings.Index(string(body)[start:], "\"")
					if end != -1 {
						reason = string(body)[start : start+end]
					}
				}

				w.Header().Set("X-Crowdsec-Decision", "ban")
				
				// Encode parameters for the redirect
				target := fmt.Sprintf("%s?ip=%s&reason=%s", 
					redirectURL, 
					clientIP, 
					strings.ReplaceAll(reason, " ", "+"))
				
				http.Redirect(w, r, target, http.StatusFound)
				return
			}
		}

		w.Header().Set("X-Crowdsec-Decision", "none")
		w.WriteHeader(http.StatusOK)
	})

	http.ListenAndServe(":8080", nil)
}
