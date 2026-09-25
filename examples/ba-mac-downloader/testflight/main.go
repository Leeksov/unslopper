// tf-ba-download retrieves the encrypted Apple-hosted BA archive for an
// internal TestFlight app. Authentication and cookies stay in memory.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/majd/ipatool/v2/pkg/util/machine"
	"github.com/majd/ipatool/v2/pkg/util/operatingsystem"
	"golang.org/x/term"
)

const digestSalt = "LWzxL71nAUJTbK9X54DDQU5KC6oTcBFuibEJXIZglPRkhCSmh68PREebiNDZXctOKXpIcOfbnndI2FjMveKfRYOLPfYFRTgua1vg"

type memoryKeychain struct{ values map[string][]byte }

func (m *memoryKeychain) Get(key string) ([]byte, error) {
	if value, ok := m.values[key]; ok {
		return append([]byte(nil), value...), nil
	}
	return nil, os.ErrNotExist
}
func (m *memoryKeychain) Set(key string, value []byte) error {
	m.values[key] = append([]byte(nil), value...)
	return nil
}
func (m *memoryKeychain) Remove(key string) error { delete(m.values, key); return nil }

type memoryCookieJar struct{ *cookiejar.Jar }

func (*memoryCookieJar) Save() error { return nil }

func prompt(label string, hidden bool) (string, error) {
	fmt.Fprint(os.Stderr, label)
	if hidden {
		data, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(data), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line), err
}

func uuid() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])), nil
}

func readJSON(response *http.Response) (map[string]json.RawMessage, error) {
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(data, &body); err != nil {
		return nil, err
	}
	return body, nil
}

func main() {
	appID := flag.Int64("app-id", 6815619549, "TestFlight app Apple ID")
	bundleID := flag.String("bundle-id", "com.leeksov.corealdhostedprobe", "installed app bundle ID")
	packID := flag.String("pack", "CoreALDTest", "asset-pack identifier")
	output := flag.String("output", "CoreALDTest-testflight-encrypted.aar", "output archive")
	compareRequest := flag.String("compare-request", "", "optional local request JSON for account match diagnostic")
	bootstrapFile := flag.String("bootstrap-file", "", "optional private TestFlight session JSON to renew in place")
	replayOnly := flag.Bool("replay-fresh-digest", false, "test a new Mac-generated digest using a captured session")
	authWithCaptured := flag.Bool("auth-with-captured-session", false, "reauthenticate using a saved valid session")
	flag.Parse()
	if *appID <= 0 || *bundleID == "" || *packID == "" {
		fmt.Fprintln(os.Stderr, "invalid arguments")
		os.Exit(2)
	}

	email, err := prompt("Apple ID for TestFlight: ", false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "email input failed")
		os.Exit(2)
	}
	password, err := prompt("Password (hidden): ", true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "password input failed")
		os.Exit(2)
	}

	jarBase, _ := cookiejar.New(nil)
	jar := &memoryCookieJar{jarBase}
	osAPI := operatingsystem.New()
	store := appstore.NewAppStore(appstore.Args{
		Keychain:        &memoryKeychain{values: map[string][]byte{}},
		CookieJar:       jar,
		OperatingSystem: osAPI,
		Machine:         machine.New(machine.Args{OS: osAPI}),
	})
	input := appstore.LoginInput{Email: email, Password: password}
	login, err := store.Login(input)
	if errors.Is(err, appstore.ErrAuthCodeRequired) {
		input.AuthCode, err = prompt("2FA code: ", false)
		if err == nil {
			login, err = store.Login(input)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Apple ID login failed")
		os.Exit(3)
	}
	if _, err := strconv.ParseUint(login.Account.DirectoryServicesID, 10, 64); err != nil {
		fmt.Fprintln(os.Stderr, "invalid account DSID")
		os.Exit(3)
	}
	capturedStorefront := ""
	capturedURL := ""
	capturedSessionID := ""
	if *bootstrapFile != "" {
		var bootstrap struct {
			SessionID string `json:"sessionId"`
			AccountID string `json:"accountId"`
		}
		if info, statErr := os.Stat(*bootstrapFile); statErr == nil && info.Mode().Perm()&0077 != 0 {
			fmt.Fprintln(os.Stderr, "bootstrap file permissions must be 0600")
			os.Exit(2)
		}
		if data, readErr := os.ReadFile(*bootstrapFile); readErr == nil && json.Unmarshal(data, &bootstrap) == nil {
			capturedSessionID = bootstrap.SessionID
		}
	}
	if *compareRequest != "" {
		var captured struct {
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
		}
		if data, err := os.ReadFile(*compareRequest); err == nil && json.Unmarshal(data, &captured) == nil {
			candidate := sha256.Sum256([]byte(login.Account.DirectoryServicesID + "-" + strconv.FormatInt(*appID, 10)))
			fmt.Printf("same-testflight-account=%v\n", base64.StdEncoding.EncodeToString(candidate[:]) == captured.Headers["X-Apple-TestFlight-MBA"])
			fmt.Printf("same-storefront=%v\n", login.Account.StoreFront == captured.Headers["X-Apple-Store-Front"])
			capturedStorefront = captured.Headers["X-Apple-Store-Front"]
			capturedURL = captured.URL
			capturedSessionID = captured.Headers["X-Session-Id"]
		}
	}
	if *replayOnly {
		if capturedURL == "" || capturedSessionID == "" {
			fmt.Fprintln(os.Stderr, "captured request required")
			os.Exit(2)
		}
		requestID, err := uuid()
		if err != nil {
			fmt.Fprintln(os.Stderr, "random ID failed")
			os.Exit(2)
		}
		digest := sha1.Sum([]byte(capturedSessionID + requestID + login.Account.DirectoryServicesID + digestSalt))
		request, _ := http.NewRequest(http.MethodGet, capturedURL, nil)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept-Encoding", "identity")
		request.Header.Set("Accept-Language", "en")
		request.Header.Set("X-Apple-Device-Model", "iPhone16,2")
		request.Header.Set("X-Request-Id", requestID)
		request.Header.Set("X-Session-Id", capturedSessionID)
		request.Header.Set("X-Session-Digest", hex.EncodeToString(digest[:]))
		response, err := (&http.Client{Timeout: 20 * time.Second}).Do(request)
		if err != nil {
			fmt.Fprintln(os.Stderr, "manifest replay failed")
			os.Exit(5)
		}
		status := response.StatusCode
		body, err := readJSON(response)
		if err != nil {
			fmt.Printf("fresh-digest-http=%d response-not-json\n", status)
			os.Exit(5)
		}
		var packs []json.RawMessage
		_ = json.Unmarshal(body["data"], &packs)
		fmt.Printf("fresh-digest-http=%d pack-count=%d\n", status, len(packs))
		if status != 200 {
			os.Exit(5)
		}
		randomID, err := uuid()
		if err != nil {
			return
		}
		randomSession := strings.ReplaceAll(randomID, "-", "")
		randomRequestID, err := uuid()
		if err != nil {
			return
		}
		randomDigest := sha1.Sum([]byte(randomSession + randomRequestID + login.Account.DirectoryServicesID + digestSalt))
		randomRequest, _ := http.NewRequest(http.MethodGet, capturedURL, nil)
		for key, values := range request.Header {
			randomRequest.Header[key] = append([]string(nil), values...)
		}
		randomRequest.Header.Set("X-Request-Id", randomRequestID)
		randomRequest.Header.Set("X-Session-Id", randomSession)
		randomRequest.Header.Set("X-Session-Digest", hex.EncodeToString(randomDigest[:]))
		randomResponse, err := (&http.Client{Timeout: 20 * time.Second}).Do(randomRequest)
		if err == nil {
			fmt.Printf("random-session-http=%d\n", randomResponse.StatusCode)
			randomResponse.Body.Close()
		}
		return
	}

	server := "https://testflight.apple.com"
	cookieURL, _ := url.Parse(server + "/")
	cookies := map[string]string{}
	for _, cookie := range jar.Cookies(cookieURL) {
		cookies[cookie.Name] = cookie.Value
	}
	fmt.Printf("apple-login=ok shared-cookie-count=%d\n", len(cookies))
	cookieNames := make([]string, 0, len(cookies))
	for name := range cookies {
		cookieNames = append(cookieNames, name)
	}
	sort.Strings(cookieNames)
	fmt.Printf("shared-cookie-names=%v\n", cookieNames)
	if len(cookies) == 0 {
		fmt.Fprintln(os.Stderr, "no Apple-domain cookies available to TestFlight")
		os.Exit(3)
	}

	vendorID, err := uuid()
	if err != nil {
		fmt.Fprintln(os.Stderr, "random ID failed")
		os.Exit(3)
	}
	authPayload := map[string]any{
		"deviceModel":          "iPhone16,2",
		"deviceName":           "Mac BA Research",
		"dsId":                 json.Number(login.Account.DirectoryServicesID),
		"deviceVendorId":       vendorID,
		"storeFrontIdentifier": strings.Split(login.Account.StoreFront, "-")[0],
		"storeCookies":         cookies,
	}
	client := &http.Client{Timeout: 45 * time.Second}
	var authStatus int
	var authJSON map[string]json.RawMessage
	storefronts := []string{strings.Split(login.Account.StoreFront, "-")[0], login.Account.StoreFront}
	if capturedStorefront != "" && capturedStorefront != login.Account.StoreFront {
		storefronts = append(storefronts, capturedStorefront)
	}
	for attempt, storefront := range storefronts {
		authPayload["storeFrontIdentifier"] = storefront
		authBody, _ := json.Marshal(authPayload)
		authRequest, _ := http.NewRequest(http.MethodPost, server+"/v1/session/authenticate", strings.NewReader(string(authBody)))
		authRequest.Header.Set("Content-Type", "application/json")
		authRequest.Header.Set("Accept", "application/json")
		if *authWithCaptured && capturedSessionID != "" {
			requestID, idErr := uuid()
			if idErr != nil {
				fmt.Fprintln(os.Stderr, "random ID failed")
				os.Exit(4)
			}
			digest := sha1.Sum([]byte(capturedSessionID + requestID + login.Account.DirectoryServicesID + digestSalt))
			authRequest.Header.Set("X-Request-Id", requestID)
			authRequest.Header.Set("X-Session-Id", capturedSessionID)
			authRequest.Header.Set("X-Session-Digest", hex.EncodeToString(digest[:]))
		}
		authResponse, requestErr := client.Do(authRequest)
		if requestErr != nil {
			fmt.Fprintln(os.Stderr, "TestFlight session request failed")
			os.Exit(4)
		}
		authStatus = authResponse.StatusCode
		authJSON, err = readJSON(authResponse)
		if err != nil {
			fmt.Printf("testflight-auth-http=%d response-not-json\n", authStatus)
			os.Exit(4)
		}
		fmt.Printf("testflight-auth-attempt=%d http=%d response-keys=%v\n", attempt+1, authStatus, sortedKeys(authJSON))
		if authStatus == 200 {
			break
		}
	}
	if authStatus != 200 {
		var messages []struct {
			Code        int    `json:"code"`
			MessageType string `json:"messageType"`
			Message     string `json:"message"`
		}
		_ = json.Unmarshal(authJSON["messages"], &messages)
		for _, message := range messages {
			fmt.Printf("testflight-auth-code=%d type=%s\n", message.Code, message.MessageType)
			if len(message.Message) <= 160 && regexp.MustCompile(`^[A-Za-z0-9 .,!?'-]+$`).MatchString(message.Message) {
				fmt.Printf("testflight-auth-message=%s\n", message.Message)
			}
		}
		os.Exit(4)
	}
	var session struct {
		SessionID string `json:"sessionId"`
		AccountID string `json:"accountId"`
	}
	if err := json.Unmarshal(authJSON["data"], &session); err != nil || session.SessionID == "" || session.AccountID == "" {
		fmt.Fprintln(os.Stderr, "TestFlight session fields missing")
		os.Exit(4)
	}
	if *bootstrapFile != "" {
		data, _ := json.Marshal(session)
		if err := os.WriteFile(*bootstrapFile, data, 0600); err != nil {
			fmt.Fprintln(os.Stderr, "session refresh save failed")
			os.Exit(4)
		}
	}

	manifestURL, _ := url.Parse(server + "/v3/accounts/" + url.PathEscape(session.AccountID) + "/apps/" + strconv.FormatInt(*appID, 10) + "/asset-packs")
	query := manifestURL.Query()
	query.Set("buildBundleID", *bundleID)
	query.Set("platform", "ios")
	manifestURL.RawQuery = query.Encode()
	requestID, err := uuid()
	if err != nil {
		fmt.Fprintln(os.Stderr, "random ID failed")
		os.Exit(4)
	}
	digestInput := session.SessionID + requestID + login.Account.DirectoryServicesID + digestSalt
	digest := sha1.Sum([]byte(digestInput))
	manifestRequest, _ := http.NewRequest(http.MethodGet, manifestURL.String(), nil)
	manifestRequest.Header.Set("Content-Type", "application/json")
	manifestRequest.Header.Set("Accept-Encoding", "identity")
	manifestRequest.Header.Set("Accept-Language", "en")
	manifestRequest.Header.Set("X-Apple-Device-Model", "iPhone16,2")
	manifestRequest.Header.Set("X-Request-Id", requestID)
	manifestRequest.Header.Set("X-Session-Id", session.SessionID)
	manifestRequest.Header.Set("X-Session-Digest", hex.EncodeToString(digest[:]))
	// The MBA header is derivable from the account DSID and app ID. The
	// recorded endpoint accepted requests without it, but include it.
	mba := sha256.Sum256([]byte(login.Account.DirectoryServicesID + "-" + strconv.FormatInt(*appID, 10)))
	manifestRequest.Header.Set("X-Apple-TestFlight-MBA", base64.StdEncoding.EncodeToString(mba[:]))
	manifestResponse, err := client.Do(manifestRequest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "TestFlight manifest request failed")
		os.Exit(5)
	}
	manifestStatus := manifestResponse.StatusCode
	manifestJSON, err := readJSON(manifestResponse)
	if err != nil {
		fmt.Printf("manifest-http=%d response-not-json\n", manifestStatus)
		os.Exit(5)
	}
	var packs []struct {
		Attributes struct {
			Identifier  string `json:"providerReferenceIdentifier"`
			DownloadURL string `json:"downloadUrl"`
			Size        int64  `json:"downloadSizeInBytes"`
		} `json:"attributes"`
	}
	_ = json.Unmarshal(manifestJSON["data"], &packs)
	fmt.Printf("manifest-http=%d pack-count=%d\n", manifestStatus, len(packs))
	if manifestStatus != 200 {
		os.Exit(5)
	}
	for _, pack := range packs {
		if pack.Attributes.Identifier != *packID {
			continue
		}
		cdn, err := url.Parse(pack.Attributes.DownloadURL)
		if err != nil || cdn.Scheme != "https" || cdn.Hostname() != "odr.itunes.apple.com" || pack.Attributes.Size < 1 {
			fmt.Fprintln(os.Stderr, "invalid CDN descriptor")
			os.Exit(5)
		}
		fetch := &http.Client{Timeout: 5 * time.Minute}
		response, err := fetch.Get(cdn.String())
		if err != nil {
			fmt.Fprintln(os.Stderr, "CDN request failed")
			os.Exit(6)
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			fmt.Printf("cdn-http=%d\n", response.StatusCode)
			os.Exit(6)
		}
		file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "output creation failed")
			os.Exit(6)
		}
		count, copyErr := io.Copy(file, io.LimitReader(response.Body, pack.Attributes.Size+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || count != pack.Attributes.Size {
			fmt.Printf("download-incomplete bytes=%d expected=%d\n", count, pack.Attributes.Size)
			os.Exit(6)
		}
		fmt.Printf("download-complete encrypted-bytes=%d output=%s\n", count, *output)
		return
	}
	fmt.Fprintln(os.Stderr, "requested pack unavailable")
	os.Exit(5)
}

func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	// The keys are fixed schema names; sorting makes output deterministic.
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}
