# CoreALD license-chunk path

This is a bounded analysis of iOS 26.0.1 `ManagedBackgroundAssetsHelper`
and `CoreALD` 4.1.0. It describes what the native call sites pass to CoreALD
and what synthetic emulation reaches. It does not identify the content
cipher or reconstruct a valid license.

## Call sequence

The helper calls four CoreALD exports through shared-cache branch islands.
The island destinations were read from the running `backgroundassets.user`
process and matched to the helper's original `BL` sites. Exact addresses are
in [the call-site evidence](evidence/coreald_chunk_call_islands_26_0_1.json).

| Helper | CoreALD export | Observed role |
| --- | --- | --- |
| `sub_1D1F99004` | `_QSIlMWCo` | Deallocates a license response, inferred from the helper's failure message. `X0` is passed through from its caller. |
| `BAStartLicenseCryptSession` | `_CWeMQvFE` | Receives two byte buffers, their lengths, and an output session pointer. The helper calls these inputs “keys” in a diagnostic string. |
| `BADecryptLicenseChunk` | `_FbLnABIk` | Receives the session pointer and a descriptor for one nonempty chunk. |
| `sub_1D1F9CBE8` | `_OZpDoyky` | Receives the session pointer during cleanup; the cleanup role is inferred from the call order and surrounding code. |

The observed `_CWeMQvFE` call registers are `X0=buffer A`, `X1=length A`,
`X2=buffer B`, `X3=length B`, and `X4=&session`. The helper converts both
Swift `Data` values to contiguous byte storage and checks that both lengths
fit in 32 bits before making the call. A zero return is treated as success.

For `_FbLnABIk`, `BADecryptLicenseChunk` passes `X0=session` and `X1` pointing
to a stack descriptor. Its observed fields are:

| Offset | Value placed by the helper |
| ---: | --- |
| `+0x00` | 32-bit value `1` |
| `+0x08` | Pointer to a 32-bit length value |
| `+0x10` | Pointer to mutable chunk bytes |
| `+0x18` | Chunk byte length |

The helper skips an empty chunk. For a nonempty chunk it checks that the
length is at most `0x8000` (32 KiB), obtains writable Swift `Data` storage,
and invokes CoreALD with the descriptor above. No separate output-byte
pointer is visible in this call preparation, so an in-place byte update is
the likely intent; that remains an inference until a successful call is
observed. The helper tests CoreALD's return value and propagates a failure.

## What synthetic Chomper execution establishes

Chomper required explicit rebasing of this extracted shared-cache image's
pointer slots in emulator memory. With synthetic non-null arguments, the
`_FbLnABIk` path went through `0x24252FBB4`, called `0x242A66658`, and
the next `BRAA` reached `0x242A66744`. The qword used to construct that
context-derived pointer is an authenticated entry in the on-disk table.
The synthetic path continued through 24 authenticated transfers and returned
`0xFFFF57FF`. Its input had no valid initialized session, so this trace does
not represent successful chunk decryption.

A separate synthetic initialization attempt supplied controlled byte buffers
of several sizes to `_CWeMQvFE`. Zero-length buffers returned
`0xFFFFE4A6`; tested nonzero lengths from 1 through 256 bytes returned
`0xFFFFE4A4`, and no session pointer was produced. A Unicorn memory-read
hook observed **zero reads from either input buffer** in these runs. Thus
the failure occurred before this emulation reached the byte contents; it
does not establish a key format or cipher. Those are observed numeric
results. The helper maps `-7002` to “A parameter is invalid.” and `-7004`
to “A memory failure occurred.” via its status conversion and error-string
switch. Tracing the nonzero path backward found a CoreALD internal call at
`0x24277A3EC` requesting `0xE0` (224) bytes and returning null; the failure
is then written through the context at `0x242783ED4`. Supplying a bare
buffer for that allocation in a separate experiment reaches further code
but does not create a valid session, because later code expects additional
context state. The probe used synthetic buffer
contents, an older Chomper rootfs, and a stubbed stack-probe import. A
missing emulated system prerequisite remains possible. The bounded case
matrix is in the [initialization evidence](evidence/coreald_chomper_init_26_0_1.json).

The same early failure was reproduced **on the iOS 26.0.1 device**, using
Frida in an isolated `sleep` process that loaded CoreALD. With non-null
buffers of lengths 32 and 16, `_CWeMQvFE` returned `-7004`, created no
session, and its internal call at `0x242EC23F0` requested 224 bytes and
returned null. Empty lengths returned `-7002`. The
[device harness](../tools/coreald_device_harness.py) records only lengths,
status codes, and allocation size/nullness; see its
[result](evidence/coreald_device_harness_26_0_1.json). Thus the specific
early failure is not solely a Chomper artifact, though this isolated
process still lacks a real license-delivery context.

The controlled 32/16-byte call was repeated inside the protected
`backgroundassets.user` daemon using the arm64e Frida server. CoreALD was
already loaded there, yet the same 224-byte internal request returned null,
`_CWeMQvFE` returned `-7004`, and no session was created. Empty lengths
returned `-7002`. The [daemon evidence](evidence/coreald_daemon_probe_26_0_1.json)
contains only lengths, status codes, and allocation nullness. A successful
license-delivery transaction is still needed before attributing this error
to a specific validity check or studying the byte transformation.

[`coreald_runtime_probe.py`](../tools/coreald_runtime_probe.py) can watch a
real session without reading or recording key and chunk bytes. It records
buffer lengths, chunk-descriptor shape, and return statuses, then detaches.
The [CoreALD iOS test host](../examples/coreald-ios-probe/README.md) can
exercise the same private calls using controlled buffers in its own app
process; it cannot manufacture an Apple-hosted asset license.
The initial 10-second watch attached successfully but observed no calls.
For a device whose Frida server listens only on loopback, forward the port
over SSH and run:

```text
ssh -N -L 37142:127.0.0.1:27042 root@<device>
python3 tools/coreald_runtime_probe.py --endpoint 127.0.0.1:37142 --seconds 60
```

The remaining decisive evidence is a real, successful
`BADecryptLicenseChunk` invocation. The input-buffer lengths, branch path,
return status, and before/after chunk bytes would distinguish validation
from the byte transformation. No license material is included in this repo.

## Apple-hosted managed asset pack control experiment

An independent iOS 26 test app (`com.leeksov.corealdhostedprobe`) and
`CoreALDTest` managed asset pack were uploaded to App Store Connect as
TestFlight build 1.0 (1) and pack version 1. The pack processed to
`READY_FOR_TESTING`, and the app reported a successful
`ensureLocalAvailability` call. Subsequent taps of that button may only
reuse the local pack, so they are not evidence of a new download.

Build 1.0 (2) added an explicit `remove(assetPackWithID:)` followed by
`ensureLocalAvailability`. The app reported `Redownloaded CoreALDTest,
version 1` during a 90-second watch of `backgroundassets.user`; the
[metadata-only capture](evidence/coreald_hosted_testflight_redownload_26_0_1.json)
contains the `ready` event and no CoreALD session or chunk calls. That
UI result confirms only that the API completed, not that bytes moved over
the network. CoreALD was also found loaded in `mobileassetd` and
`appstored`. Later watches of all three processes likewise observed no
calls, but a synchronized successful redownload was not confirmed for
those watches. These observations do not yet establish whether the small
Apple-hosted pack uses the licensed CoreALD path at all.
