#!/usr/bin/env python3
"""Renew an authorized TestFlight session and fetch an encrypted BA archive.

The bootstrap file is a credential. It contains no Apple ID password or cookie,
but must be stored mode 0600 and kept out of source control.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


ROOT = "https://testflight.apple.com"
SALT = "LWzxL71nAUJTbK9X54DDQU5KC6oTcBFuibEJXIZglPRkhCSmh68PREebiNDZXctOKXpIcOfbnndI2FjMveKfRYOLPfYFRTgua1vg"


def request_id() -> str:
    return str(uuid.uuid4()).upper()


def session_headers(session_id: str, dsid: str) -> dict[str, str]:
    identifier = request_id()
    digest = hashlib.sha1((session_id + identifier + dsid + SALT).encode()).hexdigest()
    return {
        "X-Session-Id": session_id,
        "X-Request-Id": identifier,
        "X-Session-Digest": digest,
    }


def call_json(request: urllib.request.Request) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status, body = response.status, response.read(4 << 20)
    except urllib.error.HTTPError as error:
        status, body = error.code, error.read(4 << 20)
    except urllib.error.URLError as error:
        raise RuntimeError("network request failed") from None
    try:
        return status, json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise RuntimeError(f"HTTP {status} returned non-JSON data") from None


def save_bootstrap(path: Path, data: dict) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".tf-session-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(data, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap", required=True, type=Path)
    parser.add_argument("--app-id", default="6815619549")
    parser.add_argument("--bundle-id", default="com.leeksov.corealdhostedprobe")
    parser.add_argument("--pack", default="CoreALDTest")
    parser.add_argument("--output", type=Path, default=Path("CoreALDTest-encrypted.aar"))
    args = parser.parse_args()

    if args.bootstrap.stat().st_mode & 0o077:
        raise SystemExit("bootstrap file must have mode 0600")
    bootstrap = json.loads(args.bootstrap.read_text())
    session_id = bootstrap.get("sessionId", "")
    account_id = bootstrap.get("accountId", "")
    dsid = bootstrap.get("dsid", "")
    storefront = bootstrap.get("storefront", "")
    if not (session_id and account_id and dsid.isdecimal() and storefront):
        raise SystemExit("bootstrap requires sessionId, accountId, dsid, storefront")
    if args.output.exists():
        raise SystemExit("output already exists")

    body = json.dumps({
        "deviceModel": "iPhone16,2",
        "deviceName": "Mac BA Research",
        "dsId": int(dsid),
        "deviceVendorId": request_id(),
        "storeFrontIdentifier": storefront,
        "storeCookies": {},
    }).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    headers.update(session_headers(session_id, dsid))
    status, result = call_json(urllib.request.Request(
        ROOT + "/v1/session/authenticate", data=body, headers=headers, method="POST"))
    session = result.get("data") or {}
    if status != 200 or not session.get("sessionId") or not session.get("accountId"):
        raise SystemExit(f"TestFlight session renewal failed: HTTP {status}")
    session_id, account_id = session["sessionId"], session["accountId"]
    save_bootstrap(args.bootstrap, {
        "sessionId": session_id, "accountId": account_id,
        "dsid": dsid, "storefront": storefront,
    })
    print("session-renewal-http=200")

    query = urllib.parse.urlencode({"buildBundleID": args.bundle_id, "platform": "ios"})
    url = f"{ROOT}/v3/accounts/{urllib.parse.quote(account_id)}/apps/{urllib.parse.quote(args.app_id)}/asset-packs?{query}"
    headers = {
        "Content-Type": "application/json",
        "Accept-Encoding": "identity",
        "Accept-Language": "en",
        "X-Apple-Device-Model": "iPhone16,2",
    }
    headers.update(session_headers(session_id, dsid))
    status, catalog = call_json(urllib.request.Request(url, headers=headers))
    packs = catalog.get("data") or []
    print(f"manifest-http={status} pack-count={len(packs)}")
    if status != 200:
        raise SystemExit("manifest request failed")
    match = next((item["attributes"] for item in packs
                  if item.get("attributes", {}).get("providerReferenceIdentifier") == args.pack), None)
    if match is None:
        raise SystemExit("requested pack is absent from manifest")
    cdn_url = match.get("downloadUrl", "")
    parsed = urllib.parse.urlsplit(cdn_url)
    if parsed.scheme != "https" or parsed.hostname != "odr.itunes.apple.com":
        raise SystemExit("unexpected CDN host")
    expected = int(match["downloadSizeInBytes"])
    if expected <= 0:
        raise SystemExit("invalid expected size")

    temporary = args.output.with_name(args.output.name + ".part")
    if temporary.exists():
        raise SystemExit("partial output already exists")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    count = 0
    digest = hashlib.sha256()
    try:
        try:
            response = urllib.request.urlopen(cdn_url, timeout=60)
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"CDN HTTP {error.code}") from None
        with response, os.fdopen(descriptor, "wb") as stream:
            if response.status != 200:
                raise RuntimeError(f"CDN HTTP {response.status}")
            while True:
                chunk = response.read(min(1 << 20, expected + 1 - count))
                if not chunk:
                    break
                count += len(chunk)
                digest.update(chunk)
                stream.write(chunk)
                if count > expected:
                    raise RuntimeError("CDN returned excess bytes")
        if count != expected:
            raise RuntimeError(f"download incomplete: {count} of {expected} bytes")
        os.replace(temporary, args.output)
    except Exception:
        if temporary.exists():
            temporary.unlink()
        raise
    print(f"download-complete bytes={count} sha256={digest.hexdigest()}")
    print(f"output={args.output}")


if __name__ == "__main__":
    main()
