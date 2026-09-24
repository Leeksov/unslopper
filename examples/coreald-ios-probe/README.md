# CoreALD Probe

An ad hoc iOS test host for the CoreALD 4.1.0 export ABI observed on iOS
26.0.1. It loads CoreALD at runtime, tests session creation with controlled
buffers, and reports status codes on screen. If a session is successfully
created, it submits a 32-byte synthetic chunk and releases the session.
No Apple ID data, license bytes, or chunk contents are stored or logged.

Build on macOS with Xcode and the iPhoneOS SDK:

```sh
make
```

The output is `build/CoreALDProbe.ipa`, ad hoc signed for a jailbroken test
device. The bundle identifier is `com.leeksov.corealdprobe`. Open the app and
tap **Run CoreALD checks**; it shows status codes without displaying the
input buffers. Attach a tracer to process `CoreALDProbe`; the existing
[`tools/coreald_runtime_probe.py`](../../tools/coreald_runtime_probe.py) supports
`--process CoreALDProbe`.

On the iOS 26.0.1 test device, a complete bundle is registered under
`com.leeksov.corealdprobe`. The screen was locked during this run, so the
first launch and private-framework calls remain unverified.

This exercises CoreALD in an app process with the device's real dyld and
pointer authentication. It is a private-API harness, not an Apple-hosted
Background Assets app. A successful Apple-hosted download and license
delivery require a configured app, downloader extension, asset pack, and
[App Store Connect or TestFlight distribution](https://developer.apple.com/documentation/backgroundassets/downloading-apple-hosted-asset-packs).
