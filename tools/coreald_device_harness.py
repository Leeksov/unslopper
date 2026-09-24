"""Run controlled CoreALD session calls in an isolated iOS process.

The target must be a short-lived `sleep` process or CoreALDProbe app on the
iOS 26.0.1 test device. Only input lengths, status codes, and one internal
allocation's size/nullness are reported; no input or license bytes are sent.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


AGENT = r"""
try {
  const m = Module.load('/System/Library/PrivateFrameworks/CoreALD.framework/CoreALD');
  if (m.size !== 0xB4C700)
    throw new Error('CoreALD image differs from audited iOS 26.0.1 image');

  const start = new NativeFunction(m.getExportByName('CWeMQvFE'), 'int',
    ['pointer', 'ulong', 'pointer', 'ulong', 'pointer']);
  const stop = new NativeFunction(m.getExportByName('OZpDoyky'), 'int', ['pointer']);
  const allocator = m.base.add(0x242EC23F0 - 0x2424CD000);
  let current = null;
  const hook = Interceptor.attach(allocator, {
    onEnter(args) { this.requested = parseInt(args[0].toString(), 16); },
    onLeave(retval) {
      if (current !== null)
        current.allocations.push({requested: this.requested, returnedNull: retval.isNull()});
    }
  });

  const a = Memory.alloc(256), b = Memory.alloc(256);
  a.writeByteArray(Array.from({length: 256}, (_, i) => i));
  b.writeByteArray(Array.from({length: 256}, (_, i) => 255 - i));
  const output = Memory.alloc(Process.pointerSize);
  const cases = [[0, 0], [32, 16]];
  const results = [];
  for (const [lenA, lenB] of cases) {
    current = {lenA, lenB, allocations: []};
    output.writePointer(NULL);
    current.status = start(a, lenA, b, lenB, output);
    const session = output.readPointer();
    current.sessionCreated = !session.isNull();
    if (!session.isNull()) current.stopStatus = stop(session);
    results.push(current);
  }
  current = null;
  hook.detach();
  send({imageSize: m.size, results});
} catch (e) {
  send({error: String(e)});
}
"""


def main():
    import frida

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="127.0.0.1:37142")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    device = frida.get_device_manager().add_remote_device(args.endpoint)
    process = next((p for p in device.enumerate_processes() if p.pid == args.pid), None)
    if process is None:
        raise ValueError("target PID is not running")
    if process.name not in {"sleep", "CoreALDProbe"}:
        raise ValueError(f"refusing system process {process.name!r}; use an isolated test host")

    session = device.attach(args.pid)
    messages = []
    script = session.create_script(AGENT)
    script.on("message", lambda message, data: messages.append(message.get("payload", message)))
    try:
        script.load()
    finally:
        session.detach()
    if len(messages) != 1:
        raise RuntimeError(f"expected one agent result, received {len(messages)}")
    result = {"process": process.name, "pid": args.pid, **messages[0]}
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
