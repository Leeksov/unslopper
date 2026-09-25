# TestFlight Background Assets: encrypted Mac fetch

## Confirmed result

On September 24–25, 2026, an owned internal TestFlight app (`com.leeksov.corealdhostedprobe`, Apple ID `6815619549`) and its Apple-hosted `CoreALDTest` asset pack were used as a control. The public App Store Media API catalog returned zero packs for this TestFlight-only app. `+[ASDBackgroundAssets testFlightDownloadManifestRequestForStoreItemIdentifier:bundleIdentifier:error:]` instead returned a request to `testflight.apple.com/v3/accounts/<accountID>/apps/<appID>/asset-packs` with `buildBundleID` and `platform=ios` query parameters.

Replaying that request from the Mac returned HTTP 200 with one pack and a signed `odr.itunes.apple.com` URL. A Mac GET of that URL returned 132,041 bytes. The encrypted output's SHA-256 is `c00df669c0a4b5ac99f4be1004617305b7afd29b2455bfb62942422eaf04f8bf`; the source `.aar` hash is `21885c2ef3d66c808bcf6f782939095b11bcbc5bf114b717f73f1c8a751b4ac1`. `aa list` reads the source and rejects the Apple-delivered bytes. Neither the license key nor the pack's plaintext was recovered from the CDN copy.

## Request construction found in TestFlightServices

The iOS 26.0.1 `TestFlightServices.framework` binary is not FairPlay encrypted. Its `TFServiceExtensionHandler` constructs the manifest request through `TFHallidayService`, `TFURLRequestEncoder`, and `TFAuthenticationManager`. Relevant observed methods and image-relative addresses:

| Method | Address | Finding |
| --- | ---: | --- |
| `-[TFServiceExtensionHandler fetchBAManifestRequestForStoreItemID:bundleID:reply:]` | `0xA9028` | Authorizes, then creates a manifest request. |
| Its authorization completion block | `0xA9184` | Adds TestFlight authentication headers to the encoded request. |
| `-[TFHallidayService composeBAManifestRequestForAppID:bundleID:platform:]` | `0x7FF84` | Builds `/v3/accounts/<accountID>/apps/<appID>/asset-packs`. |
| `-[TFAuthenticationManager generateBAManifestRequestAuthHeadersForAppID:]` | `0x45704` | Adds `X-Apple-TestFlight-MBA`. |
| `-[TFAuthSessionInfo generateURLRequestAuthHeadersWithAccountDSID:]` | `0x46700` | Generates session ID, request ID, and digest headers. |
| `-[TFAuthenticationManager _authenticateWithHalliday]` | `0x438AC` | POSTs to `/v1/session/authenticate`. |

`X-Session-Digest` is lowercase SHA-1 hex of the concatenated `sessionID`, uppercase request UUID, decimal DSID, and a fixed literal present in the binary. `X-Apple-TestFlight-MBA` is Base64 SHA-256 of `DSID + "-" + appID`. The digest calculation was validated: a fresh UUID and digest generated on the Mac with the captured session ID returned HTTP 200 and the pack. A random session ID and matching recomputed digest returned HTTP 401. The manifest endpoint also accepted a bounded seven-header request: `Content-Type`, `Accept-Encoding`, `Accept-Language`, `X-Apple-Device-Model`, `X-Request-Id`, `X-Session-Id`, and `X-Session-Digest`. The recorded device-specific `X-Apple-AMD-M` and `X-Apple-TestFlight-MBA` headers were not individually required for this manifest response.

## Session bootstrap limit

`ipatool`'s emulated-SAP App Store login was run with an in-memory keychain and cookie jar. It returned the same DSID as the TestFlight account on the iPhone (checked by recomputing `X-Apple-TestFlight-MBA`) and nine Apple-domain cookies. An initial Mac POST to `/v1/session/authenticate` returned HTTP 401, code 102, `The credentials for this app are invalid.` Trying the full storefront, the numeric storefront identifier, and the device-observed storefront did not change that response. Omitting the storefront yielded HTTP 400, code 10008. The exact missing bootstrap prerequisite is not established; differences between ipatool's App Store cookies and the iOS account's `ams_cookies`, or device registration checks, remain candidates.

When the Mac POST supplied a previously valid TestFlight session ID with a fresh, locally computed digest, it returned HTTP 200 with a renewed `sessionId` and `accountId`. A further test sent **empty `storeCookies` and no Apple ID credentials**, and renewal still returned HTTP 200. The Mac then fetched a new signed manifest URL and downloaded the encrypted pack; two consecutive runs produced the same SHA-256 as the earlier Apple-delivered copy. A private mode-`0600` bootstrap JSON holding the session ID, account ID, DSID, and storefront is sufficient for this renewal path. The [passwordless Mac tool](../examples/ba-mac-downloader/testflight/bootstrap_fetch.py) refreshes that file after successful authorization. It does not yet create the first TestFlight session without an existing one.

No signed CDN URL, cookie value, session ID, account DSID, or password is included in this repository. No device logs were read.
