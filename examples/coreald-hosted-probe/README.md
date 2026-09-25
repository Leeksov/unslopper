# CoreALD Hosted Background Assets Probe

This small iOS 26 app requests an Apple-hosted, on-demand managed asset pack. It is intended to create a genuine TestFlight Background Assets transaction for metadata-only CoreALD tracing. The included pack contains only a known text marker; no license material is stored in this project.

## Build the pack

```sh
cd Pack
python3 make_payload.py
xcrun ba-package evaluate Manifest.json
xcrun ba-package Manifest.json -o CoreALDTest.aar
```

## Configure and build the app

Change both bundle IDs and the app-group ID in `project.yml`, `App/Info.plist`, and the two entitlement files to identifiers registered to your Apple Developer team. In Xcode, select that team for both targets and register the shared App Group capability. Then generate the project with `xcodegen generate`, archive it, and upload the build to App Store Connect for internal TestFlight testing. For an unsigned local compile, pass `CODE_SIGNING_ALLOWED=NO` to `xcodebuild`.

Create the App Store Connect app record before uploading the pack. Once the app has an Apple ID, upload `CoreALDTest.aar` with `xcrun altool --upload-asset-pack Pack/CoreALDTest.aar --apple-id <app-apple-id>` and authenticated App Store Connect credentials. Wait for the pack to finish processing and become available to the internal TestFlight release. Install the TestFlight build, open it, and tap **Download test pack**.

The app only displays download status or an error. The pack holds a text marker and 128 KiB of deterministic test data so it has multiple 32 KiB chunks after packaging. Any runtime tracing should record call names, sizes, return codes, and session lifetime, without recording account data, license blobs, or signed URLs.

## Current App Store Connect test record

- App: `CoreALD Hosted Probe` (`com.leeksov.corealdhostedprobe`), Apple ID `6815619549`.
- Developer team: `F8A8NWPL78`.
- Build `1.0 (1)` was uploaded and processed as valid on September 24, 2026.
- Asset pack `CoreALDTest`, version `1`, has `READY_FOR_TESTING` status.
- The internal `Testers` group has the build and invited the Brijneet Bhasin account. Build 1 was installed from TestFlight and reported successful asset availability; an actual network transfer was not independently verified.
- Build `1.0 (2)` was uploaded and processed as valid. It adds a **Remove and redownload** button to distinguish a new availability request from a cached `ensureLocalAvailability` call. A device reported `Redownloaded CoreALDTest, version 1`, while a metadata-only CoreALD watch in `backgroundassets.user` observed no session or chunk calls; this does not prove whether network bytes were transferred.
- The [Mac TestFlight research](../../docs/testflight_ba_mac_fetch.md) downloaded the 132,041-byte encrypted Apple-hosted version of this pack. Its SHA-256 differs from the source `.aar` and is stable across repeated Mac fetches.
