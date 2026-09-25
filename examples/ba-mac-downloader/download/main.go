package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type catalogDocument struct {
	Data []struct {
		Attributes struct {
			Identifier string `json:"providerReferenceIdentifier"`
			URL        string `json:"downloadUrl"`
			Size       int64  `json:"downloadSizeInBytes"`
		} `json:"attributes"`
	} `json:"data"`
}

func main() {
	catalogPath := flag.String("catalog", "catalog-control.json", "catalog JSON produced by ba-catalog")
	identifier := flag.String("identifier", "control-ios-packfiles", "asset-pack provider reference identifier")
	output := flag.String("output", "", "output .aar path; defaults to <identifier>.aar")
	flag.Parse()
	if !regexp.MustCompile(`^[A-Za-z0-9._-]+$`).MatchString(*identifier) {
		fatal("identifier-invalid")
	}
	if *output == "" {
		*output = *identifier + ".aar"
	}
	data, err := os.ReadFile(*catalogPath)
	if err != nil {
		fatal("catalog-unavailable")
	}
	var catalog catalogDocument
	if json.Unmarshal(data, &catalog) != nil {
		fatal("catalog-invalid")
	}
	var source string
	var expected int64
	for _, item := range catalog.Data {
		if item.Attributes.Identifier == *identifier {
			source, expected = item.Attributes.URL, item.Attributes.Size
			break
		}
	}
	parsed, err := url.Parse(source)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != "odr.itunes.apple.com" ||
		!strings.HasSuffix(parsed.Path, ".aar") || expected <= 0 {
		fatal("asset-url-invalid")
	}
	if existing, err := os.Stat(*output); err == nil {
		if existing.Size() == expected {
			fmt.Printf("already-complete-bytes=%d\n", expected)
			return
		}
		fatal("existing-output-size-mismatch")
	}

	partial := *output + ".part"
	file, err := os.OpenFile(partial, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		fatal("output-open-failed")
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		fatal("output-stat-failed")
	}
	start := stat.Size()
	if start > expected {
		fatal("partial-file-too-large")
	}
	if start == expected {
		if os.Rename(partial, *output) != nil {
			fatal("rename-failed")
		}
		fmt.Printf("complete-bytes=%d\n", expected)
		return
	}

	request, err := http.NewRequest(http.MethodGet, source, nil)
	if err != nil {
		fatal("request-invalid")
	}
	if start > 0 {
		request.Header.Set("Range", fmt.Sprintf("bytes=%d-", start))
	}
	client := &http.Client{Transport: &http.Transport{
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}}
	response, err := client.Do(request)
	if err != nil {
		fatal("download-request-failed")
	}
	defer response.Body.Close()
	fmt.Printf("http-status=%d resume-from=%d expected-bytes=%d\n", response.StatusCode, start, expected)
	if start == 0 && response.StatusCode != http.StatusOK {
		fatal("download-status-invalid")
	}
	if start > 0 {
		if response.StatusCode != http.StatusPartialContent {
			fatal("resume-not-supported")
		}
		if !strings.HasPrefix(response.Header.Get("Content-Range"), "bytes "+strconv.FormatInt(start, 10)+"-") {
			fatal("resume-range-mismatch")
		}
	}
	if _, err = file.Seek(start, io.SeekStart); err != nil {
		fatal("seek-failed")
	}
	lastReport := time.Now()
	buffer := make([]byte, 1<<20)
	for {
		n, readErr := response.Body.Read(buffer)
		if n > 0 {
			written, writeErr := file.Write(buffer[:n])
			start += int64(written)
			if writeErr != nil || written != n {
				fatal("write-failed")
			}
			if time.Since(lastReport) >= 10*time.Second {
				fmt.Printf("downloaded-bytes=%d percent=%.2f\n", start, 100*float64(start)/float64(expected))
				lastReport = time.Now()
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			fatal("download-interrupted")
		}
	}
	if file.Sync() != nil {
		fatal("sync-failed")
	}
	if start != expected {
		fatal("download-size-mismatch")
	}
	if file.Close() != nil || os.Rename(partial, *output) != nil {
		fatal("rename-failed")
	}
	fmt.Printf("complete-bytes=%d\n", expected)
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
