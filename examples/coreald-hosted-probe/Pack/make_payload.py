#!/usr/bin/env python3
"""Write deterministic, poorly compressible bytes for a multi-chunk test pack."""

from hashlib import sha256
from pathlib import Path

destination = Path(__file__).parent / "Payload" / "payload.bin"
with destination.open("wb") as output:
    for counter in range(4096):
        output.write(sha256(f"CoreALDTest-v1:{counter}".encode()).digest())
print(f"Wrote {destination}: {destination.stat().st_size} bytes")
