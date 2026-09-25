# Standalone Apple-hosted Background Assets downloader (research build)

This command-line tool retrieves **encrypted** Apple-hosted asset-pack archives without calling AppleMediaServices, StoreKit, or Keychain. It uses the SAP/FairPlay emulation in [ipatool](https://github.com/majd/ipatool) to produce `X-Apple-ActionSignature`, fetches a Media API Bearer token, reads the asset-pack catalog, and downloads a selected `.aar` archive with HTTP range resume. It never prints Bearer tokens or signed CDN URLs. Go's standard HTTPS implementation may use the operating system's public certificate trust APIs.

The downloaded archives are encrypted. An Apple ID purchase alone does not provide the decryption key. Apple's [Frameworks Engineer statement](https://developer.apple.com/forums/thread/841376) says that Apple validates a device attestation before delivering that key. Decryption and a device-independent license request are outside this build's verified capabilities.

## Build

Requires Go 1.25 or later. From this directory:

```sh
go build -o ba-catalog ./token
go build -o ba-download ./download
```

The Go module pins an ipatool commit containing its emulated SAP signer. No Apple private macOS framework is imported by these commands.

For an environment with no macOS framework calls at all, Linux x86-64 binaries can be built with:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ba-catalog-linux-amd64 ./token
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ba-download-linux-amd64 ./download
```

The Linux builds compile successfully; their network behavior has not been run-tested here.

## Control Ultimate Edition

```sh
./ba-catalog
./ba-download --identifier control-ios-presets
./ba-download --identifier control-ios-packfiles
```

`ba-catalog` defaults to App Store item `6502953520`, US storefront, and iPhone platform. It writes `catalog-control.json` with mode `0600`. The catalog contains temporary signed download URLs, so do not publish it. The tool lists pack identifiers and compressed byte counts without printing URLs. The current catalog lists `control-ios-presets` (1,174 bytes) and `control-ios-packfiles` (27,733,980,588 bytes).

To target another app or storefront:

```sh
./ba-catalog --app-id <App-Store-ID> --country <two-letter-code> --platform iphone --output catalog.json
./ba-download --catalog catalog.json --identifier <pack-identifier>
```

`ba-download` writes `<identifier>.aar.part` while transferring and renames it to `<identifier>.aar` only after the expected number of bytes arrives. Re-run the same command to resume. If the CDN URL has expired, run `ba-catalog` again before resuming. Ensure there is enough free disk space for the compressed pack.

The catalog and encrypted CDN archives are retrievable without Apple ID credentials. An Apple ID login can prove ownership of the app, but it does not replace the device-attested Background Assets license required for decryption.

## Signing flow verified for `/apiToken`

1. The `appstored` bag provides SAP setup endpoints and a `signed-actions` policy.
2. The policy for `apiToken` selects, in order, `x-apple-store-front`, `x-apple-client-application`, `x-request-timestamp`, and the `clientId` query value. Missing values are omitted. Their UTF-8 bytes are concatenated without separators.
3. ipatool's emulated FairPlay SAP session signs those bytes using `cp2g1b9ro`, `Mib5yocT`, and `Fc3vhtJDvr` and Base64-encodes the result as `X-Apple-ActionSignature`.
4. `GET /apiToken` returns a Bearer token for the registered `appstore` client. The same token authorized `GET /v1/catalog/us/asset-packs` for Control.

This tool currently uses the verified `appstore` token client and the bag endpoints observed on 2026-09-23. Apple can change this private protocol.

## Internal TestFlight asset packs (experimental)

After one authorized TestFlight session has been bootstrapped, the Python command renews that session and downloads the encrypted pack entirely on the Mac. It uses no Apple ID password, cookie, Keychain, private macOS framework, or connected iPhone:

```sh
python3 testflight/bootstrap_fetch.py \
  --bootstrap /private/path/testflight-bootstrap.json \
  --app-id 6815619549 --bundle-id com.leeksov.corealdhostedprobe \
  --pack CoreALDTest --output CoreALDTest-encrypted.aar
```

The bootstrap JSON must have mode `0600` and contain `sessionId`, `accountId`, `dsid`, and `storefront` from the authorized TestFlight account. The command sends an empty `storeCookies` object and a locally calculated session digest to `/v1/session/authenticate`. Apple returned HTTP 200 and a renewed session in this experiment. The command atomically refreshes the bootstrap file, fetches `/v3/accounts/<accountId>/apps/<appId>/asset-packs`, and downloads the encrypted CDN archive. The bootstrap file is a credential: keep it private and do not commit it.

For the owned test app, two consecutive passwordless Mac runs fetched 132,041 encrypted bytes with SHA-256 `c00df669c0a4b5ac99f4be1004617305b7afd29b2455bfb62942422eaf04f8bf`. Both match the independent Mac CDN fetch and differ from the 132,041-byte source archive. `aa list` reads the source archive and rejects the Apple-delivered copy.

**Current limit:** The *first* TestFlight `sessionId` cannot yet be obtained from Apple ID credentials alone. The separate `testflight` Go command explores this: ipatool's App Store login returns the same account DSID and nine Apple-domain cookies, but an initial TestFlight `/v1/session/authenticate` request returns HTTP 401, code 102. A random session ID returns HTTP 401. The first bootstrap still depends on an existing authorized TestFlight session; subsequent refreshes and encrypted downloads run on the Mac with the Python command above.
