"""Watch CoreALD session calls on a live iOS 26.0.1 process.

Records only call sizes, descriptor shape, and return statuses. It never
reads license-key or chunk bytes, and detaches after the requested duration.
Connect through a local SSH forward to the device's Frida server.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path


AGENT = r"""
const m = Process.getModuleByName('CoreALD');
if (m.size !== 0xB4C700) throw new Error('CoreALD size differs from audited iOS 26.0.1 image');
const slide = m.base.sub(ptr('0x2424cd000'));
const address = staticEA => ptr(staticEA).add(slide);

function attach(staticEA, handlers) {
  Interceptor.attach(address(staticEA), handlers);
}

attach('0x242b7ed44', {
  onEnter(args) {
    this.output = args[4];
    send({event: 'start_enter', lenA: parseInt(args[1].toString(), 16),
          lenB: parseInt(args[3].toString(), 16)});
  },
  onLeave(retval) {
    let created = null;
    try { created = !this.output.readPointer().isNull(); } catch (_) {}
    send({event: 'start_leave', status: retval.toInt32(), sessionCreated: created});
  }
});

attach('0x24252fb5c', {
  onEnter(args) {
    let info = {event: 'chunk_enter', sessionNonNull: !args[0].isNull()};
    try {
      const d = args[1];
      info.kind = d.readU32();
      info.length = d.add(0x18).readU64().toNumber();
      this.data = d.add(0x10).readPointer();
      info.dataNonNull = !this.data.isNull();
      info.lengthPtrNonNull = !d.add(0x08).readPointer().isNull();
      this.sampleLength = this.data.isNull() ? 0 : Math.min(info.length, 64);
      if (this.sampleLength > 0) this.before = new Uint8Array(this.data.readByteArray(this.sampleLength));
    } catch (e) { info.error = String(e); }
    send(info);
  },
  onLeave(retval) {
    let changed = null;
    try {
      if (this.before) {
        const after = new Uint8Array(this.data.readByteArray(this.sampleLength));
        changed = after.some((byte, index) => byte !== this.before[index]);
      }
    } catch (_) {}
    send({event: 'chunk_leave', status: retval.toInt32(),
          sampledBytes: this.sampleLength || 0, sampledBytesChanged: changed});
  }
});

attach('0x242512cc0', {
  onEnter(args) { send({event: 'stop_enter', sessionNonNull: !args[0].isNull()}); },
  onLeave(retval) { send({event: 'stop_leave', status: retval.toInt32()}); }
});

const helper = Process.findModuleByName('ManagedBackgroundAssetsHelper');
if (helper) {
  const helperSlide = helper.base.sub(ptr('0x1d1f77000'));
  for (const [staticEA, event] of [
    ['0x1d1f9a0fc', 'helper_session_start'],
    ['0x1d1f9a9c8', 'helper_license_chunk'],
    ['0x1d1f9ace4', 'helper_coreald_chunk_wrapper']
  ]) {
    try {
      Interceptor.attach(ptr(staticEA).add(helperSlide), {
        onEnter() { send({event}); }
      });
      send({event: 'hook_ready', target: event});
    } catch (error) { send({event: 'hook_error', target: event, detail: String(error)}); }
  }
}

const managed = Process.findModuleByName('ManagedBackgroundAssets');
if (managed) {
  const exports = managed.enumerateExports();
  for (const [needle, event] of [
    ['DecryptionProcessorC4keysAC', 'processor_init'],
    ['DecryptionProcessorC10byteStream', 'processor_stream']
  ]) {
    const hit = exports.find(item => item.name.includes(needle) && item.name.endsWith('cfC'))
      || exports.find(item => item.name.includes(needle) && item.name.endsWith('Tj'));
    if (hit) {
      try {
        Interceptor.attach(hit.address.strip(), {
          onEnter() { send({event}); }
        });
        send({event: 'hook_ready', target: event});
      } catch (error) { send({event: 'hook_error', target: event, detail: String(error)}); }
    }
  }
}

send({event: 'ready', moduleBase: m.base.toString()});
"""


def main():
    import frida

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="127.0.0.1:37142")
    parser.add_argument("--device-id", help="Use an already discovered Frida device instead of a TCP endpoint")
    parser.add_argument("--process", action="append", help="Process name or PID to watch; may be repeated")
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    device = (frida.get_device(args.device_id) if args.device_id else
              frida.get_device_manager().add_remote_device(args.endpoint))
    events = []
    sessions = []
    scripts = []

    def message_handler(process):
        def on_message(message, data):
            payload = message.get("payload", message)
            event = {"process": process, **payload} if isinstance(payload, dict) else {
                "process": process, "payload": payload}
            events.append(event)
            print(json.dumps(event, sort_keys=True), flush=True)
        return on_message

    try:
        for process in args.process or ["backgroundassets.user"]:
            target = int(process) if process.isdecimal() else process
            session = device.attach(target)
            sessions.append(session)
            script = session.create_script(AGENT)
            scripts.append(script)
            script.on("message", message_handler(process))
            script.load()
        time.sleep(max(1, args.seconds))
    finally:
        for script in scripts:
            try: script.unload()
            except Exception: pass
        for session in sessions:
            try: session.detach()
            except Exception: pass
        if args.output:
            args.output.write_text(json.dumps(events, indent=2) + "\n")
    print(json.dumps({"events": len(events), "calls": sum(
        event.get("event", "").endswith("_enter") for event in events)}))


if __name__ == "__main__":
    main()
