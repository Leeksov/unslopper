package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/majd/ipatool/v2/internal/sap"
)

func hardwareID() ([]byte, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, item := range interfaces {
		if len(item.HardwareAddr) > 0 && len(item.HardwareAddr) <= 20 {
			return append([]byte(nil), item.HardwareAddr...), nil
		}
	}
	return nil, fmt.Errorf("no hardware identifier")
}

func main() {
	clientIDFlag := flag.String("client-id", "appstore", "registered Apple Media API client")
	appID := flag.Int64("app-id", 6502953520, "App Store item ID")
	country := flag.String("country", "us", "two-letter App Store country code")
	platform := flag.String("platform", "iphone", "catalog platform")
	output := flag.String("output", "catalog-control.json", "catalog output path")
	downloadSmall := flag.Bool("download-small", false, "also download Control's small presets pack")
	flag.Parse()
	if *appID <= 0 || !regexp.MustCompile(`^[a-z]{2}$`).MatchString(*country) ||
		!regexp.MustCompile(`^[a-z]+$`).MatchString(*platform) {
		fmt.Fprintln(os.Stderr, "invalid-arguments")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	hardware, err := hardwareID()
	if err != nil {
		fmt.Fprintln(os.Stderr, "hardware-id-unavailable")
		os.Exit(2)
	}
	signer, err := sap.NewSigner(ctx, sap.Config{
		SetupURL:       "https://fpinit.itunes.apple.com/v1/signSapSetup/legacy",
		CertificateURL: "https://s.mzstatic.com/sap/setupCert.plist",
		Version:        200,
		HardwareID:     hardware,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "signer-init-failed")
		os.Exit(3)
	}
	defer signer.Close()

	clientID := *clientIDFlag
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	signedData := []byte(timestamp + clientID)
	signature, err := signer.Sign(signedData)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign-failed")
		os.Exit(3)
	}

	endpoint, _ := url.Parse("https://sf-api-token-service.itunes.apple.com/apiToken")
	query := endpoint.Query()
	query.Set("clientClass", "apple")
	query.Set("clientId", clientID)
	query.Set("os", "iOS")
	query.Set("osVersion", "26.1")
	query.Set("productVersion", "1")
	query.Set("version", "2")
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		os.Exit(3)
	}
	request.Header.Set("x-request-timestamp", timestamp)
	request.Header.Set("X-Apple-ActionSignature", base64.StdEncoding.EncodeToString(signature))
	request.Header.Set("User-Agent", "ManagedBackgroundAssets/1 iOS/26.1")
	request.Header.Set("Accept-Language", "en-US")
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		fmt.Fprintln(os.Stderr, "request-failed")
		os.Exit(4)
	}
	defer response.Body.Close()
	fmt.Printf("token-http-status=%d\n", response.StatusCode)
	if response.StatusCode != http.StatusOK {
		os.Exit(4)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		os.Exit(4)
	}
	var body map[string]any
	if json.Unmarshal(data, &body) == nil {
		keys := make([]string, 0, len(body))
		for key := range body {
			if !strings.Contains(key, "@") && len(key) < 80 {
				keys = append(keys, key)
			}
		}
		fmt.Printf("response-keys=%v\n", keys)
		if message, ok := body["message"].(string); ok && len(message) < 180 &&
			!strings.ContainsAny(message, "@/\\") {
			fmt.Printf("response-message=%s\n", message)
		}
		if status, ok := body["status"].(float64); ok {
			fmt.Printf("response-status=%d\n", int(status))
		}
		if token, ok := body["token"].(string); !ok || token == "" {
			os.Exit(4)
		}
		if token, ok := body["token"].(string); ok && token != "" && clientID == "appstore" {
			catalogURL := fmt.Sprintf("https://amp-api.apps.apple.com/v1/catalog/%s/asset-packs?filter%%5BappId%%5D=%d&platform=%s&l=en-US", *country, *appID, *platform)
			catalogRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, catalogURL, nil)
			if err != nil {
				os.Exit(5)
			}
			catalogRequest.Header.Set("Authorization", "Bearer "+token)
			catalogRequest.Header.Set("Accept-Language", "en-US")
			catalogRequest.Header.Set("User-Agent", "AppStore/3.0 iOS/26.1")
			catalogResponse, err := (&http.Client{Timeout: 30 * time.Second}).Do(catalogRequest)
			if err != nil {
				fmt.Fprintln(os.Stderr, "catalog-request-failed")
				os.Exit(5)
			}
			defer catalogResponse.Body.Close()
			fmt.Printf("catalog-http-status=%d\n", catalogResponse.StatusCode)
			if catalogResponse.StatusCode != http.StatusOK {
				os.Exit(5)
			}
			catalogData, err := io.ReadAll(io.LimitReader(catalogResponse.Body, 4<<20))
			if err != nil {
				os.Exit(5)
			}
			var catalog map[string]any
			if json.Unmarshal(catalogData, &catalog) == nil {
				catalogKeys := make([]string, 0, len(catalog))
				for key := range catalog {
					if len(key) < 80 {
						catalogKeys = append(catalogKeys, key)
					}
				}
				fmt.Printf("catalog-keys=%v\n", catalogKeys)
			}
			if catalogResponse.StatusCode == http.StatusOK {
				if err := os.WriteFile(*output, catalogData, 0600); err != nil {
					fmt.Fprintln(os.Stderr, "catalog-write-failed")
					os.Exit(5)
				}
				fmt.Printf("catalog-saved=%d\n", len(catalogData))
				packs, _ := catalog["data"].([]any)
				for _, raw := range packs {
					item, ok := raw.(map[string]any)
					if !ok {
						continue
					}
					attributes, ok := item["attributes"].(map[string]any)
					if !ok {
						continue
					}
					identifier, _ := attributes["providerReferenceIdentifier"].(string)
					size, _ := attributes["downloadSizeInBytes"].(float64)
					fmt.Printf("pack=%s bytes=%.0f\n", identifier, size)
					if !*downloadSmall || identifier != "control-ios-presets" {
						continue
					}
					downloadURL, ok := attributes["downloadUrl"].(string)
					if !ok {
						continue
					}
					parsed, err := url.Parse(downloadURL)
					if err != nil || parsed.Scheme != "https" || parsed.Hostname() != "odr.itunes.apple.com" {
						continue
					}
					assetContext, stop := context.WithTimeout(context.Background(), 60*time.Second)
					assetRequest, err := http.NewRequestWithContext(assetContext, http.MethodGet, downloadURL, nil)
					if err != nil {
						stop()
						continue
					}
					assetResponse, err := (&http.Client{Timeout: 60 * time.Second}).Do(assetRequest)
					if err != nil {
						stop()
						fmt.Fprintln(os.Stderr, "presets-download-failed")
						continue
					}
					fmt.Printf("presets-http-status=%d\n", assetResponse.StatusCode)
					if assetResponse.StatusCode == http.StatusOK {
						asset, err := io.ReadAll(io.LimitReader(assetResponse.Body, 2<<20))
						if err == nil && os.WriteFile("control-ios-presets.aar", asset, 0600) == nil {
							fmt.Printf("presets-bytes=%d\n", len(asset))
						}
					}
					assetResponse.Body.Close()
					stop()
				}
			}
		}
		return
	} else {
		fmt.Printf("response-bytes=%d\n", len(data))
	}
	os.Exit(4)
}
