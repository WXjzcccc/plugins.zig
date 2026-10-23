#!/usr/bin/env python3
"""Drive the plugin through the real lc-plugin-host (LPP v2).

    python scripts/drive.py <lc-plugin-host> <library> <file.apk> [more.apk ...] [analyzer]

The host binary bridges two peers: the plugin on one side and whatever speaks
LPP on its stdin/stdout on the other. This script plays the application side, so
it sees exactly what LovelyCarve sees: the plugin.hello handshake, then one
run.start whose inputs are the given packages, answering the plugin's file.read
calls from those files, and printing the records it emits.

The analyzer name (last argument, default apkfile) selects the entry point:
apkfile expects the selected files, apkevidence expects everything the host
resolved from the analyzer's declared inputs. Both receive the files as run
inputs, which is why the driver only has to supply file.read.

Frames are a 4-byte big-endian length followed by one MessagePack map. Host
requests carry even ids, the loader's own requests odd ones (1 is the
handshake). Binary payloads are MessagePack bin, never Base64.
"""

import collections
import json
import os
import struct
import subprocess
import sys
import tempfile
import threading

DEFAULT_ANALYZER = "winregevidence"


# --------------------------------------------------------------- MessagePack

def pack(value):
    if value is None:
        return b"\xc0"
    if value is True:
        return b"\xc3"
    if value is False:
        return b"\xc2"
    if isinstance(value, int):
        if 0 <= value < 128:
            return bytes([value])
        if value >= 0:
            for tag, fmt, limit in (
                (0xCC, ">B", 0xFF),
                (0xCD, ">H", 0xFFFF),
                (0xCE, ">I", 0xFFFFFFFF),
                (0xCF, ">Q", 1 << 64),
            ):
                if value <= limit:
                    return bytes([tag]) + struct.pack(fmt, value)
        return b"\xd3" + struct.pack(">q", value)
    if isinstance(value, str):
        raw = value.encode()
        if len(raw) < 32:
            return bytes([0xA0 | len(raw)]) + raw
        if len(raw) < 256:
            return b"\xd9" + bytes([len(raw)]) + raw
        if len(raw) < 65536:
            return b"\xda" + struct.pack(">H", len(raw)) + raw
        return b"\xdb" + struct.pack(">I", len(raw)) + raw
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) < 256:
            return b"\xc4" + bytes([len(raw)]) + raw
        if len(raw) < 65536:
            return b"\xc5" + struct.pack(">H", len(raw)) + raw
        return b"\xc6" + struct.pack(">I", len(raw)) + raw
    if isinstance(value, (list, tuple)):
        head = bytes([0x90 | len(value)]) if len(value) < 16 else b"\xdc" + struct.pack(">H", len(value))
        return head + b"".join(pack(item) for item in value)
    if isinstance(value, dict):
        head = bytes([0x80 | len(value)]) if len(value) < 16 else b"\xde" + struct.pack(">H", len(value))
        return head + b"".join(pack(k) + pack(v) for k, v in value.items())
    raise TypeError("cannot pack {!r}".format(type(value)))


def unpack(data, pos=0):
    tag = data[pos]
    pos += 1
    if tag <= 0x7F:
        return tag, pos
    if tag >= 0xE0:
        return tag - 0x100, pos
    if tag == 0xC0:
        return None, pos
    if tag == 0xC2:
        return False, pos
    if tag == 0xC3:
        return True, pos
    if tag in (0xCC, 0xCD, 0xCE, 0xCF):
        fmt = {0xCC: ">B", 0xCD: ">H", 0xCE: ">I", 0xCF: ">Q"}[tag]
        size = struct.calcsize(fmt)
        return struct.unpack(fmt, data[pos:pos + size])[0], pos + size
    if tag in (0xD0, 0xD1, 0xD2, 0xD3):
        fmt = {0xD0: ">b", 0xD1: ">h", 0xD2: ">i", 0xD3: ">q"}[tag]
        size = struct.calcsize(fmt)
        return struct.unpack(fmt, data[pos:pos + size])[0], pos + size
    if tag in (0xCA, 0xCB):
        fmt = ">f" if tag == 0xCA else ">d"
        size = struct.calcsize(fmt)
        return struct.unpack(fmt, data[pos:pos + size])[0], pos + size
    if 0xA0 <= tag <= 0xBF:
        length = tag & 0x1F
        return data[pos:pos + length].decode(), pos + length
    if tag in (0xD9, 0xDA, 0xDB):
        width = {0xD9: 1, 0xDA: 2, 0xDB: 4}[tag]
        fmt = {1: ">B", 2: ">H", 4: ">I"}[width]
        length = struct.unpack(fmt, data[pos:pos + width])[0]
        pos += width
        return data[pos:pos + length].decode(), pos + length
    if tag in (0xC4, 0xC5, 0xC6):
        width = {0xC4: 1, 0xC5: 2, 0xC6: 4}[tag]
        fmt = {1: ">B", 2: ">H", 4: ">I"}[width]
        length = struct.unpack(fmt, data[pos:pos + width])[0]
        pos += width
        return bytes(data[pos:pos + length]), pos + length
    if 0x90 <= tag <= 0x9F or tag in (0xDC, 0xDD):
        if tag in (0xDC, 0xDD):
            width = 2 if tag == 0xDC else 4
            length = struct.unpack(">H" if width == 2 else ">I", data[pos:pos + width])[0]
            pos += width
        else:
            length = tag & 0x0F
        items = []
        for _ in range(length):
            item, pos = unpack(data, pos)
            items.append(item)
        return items, pos
    if 0x80 <= tag <= 0x8F or tag in (0xDE, 0xDF):
        if tag in (0xDE, 0xDF):
            width = 2 if tag == 0xDE else 4
            length = struct.unpack(">H" if width == 2 else ">I", data[pos:pos + width])[0]
            pos += width
        else:
            length = tag & 0x0F
        result = {}
        for _ in range(length):
            key, pos = unpack(data, pos)
            value, pos = unpack(data, pos)
            result[key] = value
        return result, pos
    raise ValueError("unsupported tag 0x{:02x}".format(tag))


# ------------------------------------------------------------------ LPP I/O

def read_frame(stream):
    header = stream.read(4)
    if len(header) < 4:
        return None
    (length,) = struct.unpack(">I", header)
    body = stream.read(length)
    if len(body) < length:
        return None
    return unpack(body)[0]


def write_frame(stream, message):
    body = pack(message)
    stream.write(struct.pack(">I", len(body)) + body)
    stream.flush()


# ------------------------------------------------------------------- driver

def serve(host_in, host_out, analyzer, packages, options):
    """Answer the plugin's host calls and run one analyzer over the packages."""
    records = []
    progress = []
    warnings = []
    contents = {}
    inputs = []
    for index, (path, data) in enumerate(packages, start=1):
        file_id = "file-{}".format(index)
        contents[file_id] = data
        name = os.path.basename(path)
        inputs.append({
            "file_id": file_id,
            "name": name,
            "size": len(data),
            "root_path": name,
            "node_id": "node-{}".format(index),
            "deleted": False,
            "timestamps": {},
        })
    if analyzer.endswith("evidence"):
        target = {"kind": "evidence", "view": {"view_id": "view-1", "label": "evidence"}}
    else:
        target = {"kind": "files"}

    while True:
        message = read_frame(host_in)
        if message is None:
            return {"reason": "host closed", "records": records}
        kind = message.get("type")

        if kind == "request" and message.get("id") == 1:
            hello = message["params"]
            print("hello    ->", json.dumps({
                "protocol": hello.get("protocol"),
                "plugin": hello.get("plugin"),
                "sdk": hello.get("sdk"),
                "analyzers": hello.get("analyzers"),
                "records": [record.get("type") for record in hello.get("records") or []],
                "schema_hash": hello.get("schema_hash"),
            }, ensure_ascii=False))
            if hello.get("protocol") != 2:
                write_frame(host_out, {
                    "type": "response", "v": 2, "id": 1,
                    "error": {"code": "PROTOCOL_ERROR", "message": "protocol != 2"},
                })
                return {"reason": "protocol mismatch", "records": records}
            write_frame(host_out, {"type": "response", "v": 2, "id": 1, "result": None})
            write_frame(host_out, {
                "type": "request", "v": 2, "id": 2, "method": "run.start",
                "params": {
                    "run_id": "run-1",
                    "analyzer": analyzer,
                    "target": target,
                    "inputs": inputs,
                    "options": options,
                    "profile": {},
                    "locale": "zh-CN",
                },
            })
            continue

        if kind == "response" and message.get("id") == 2:
            return {
                "result": message.get("result"),
                "error": message.get("error"),
                "records": records,
                "progress": progress,
                "warnings": warnings,
            }

        if kind == "request":
            rid, method, params = message["id"], message["method"], message.get("params") or {}
            if method == "run.emit":
                records.extend(params.get("records") or [])
                reply = {"type": "response", "v": 2, "id": rid,
                         "result": {"accepted": len(params.get("records") or [])}}
            elif method == "run.progress":
                progress.append((params.get("current"), params.get("total"), params.get("message")))
                reply = {"type": "response", "v": 2, "id": rid, "result": None}
            elif method == "run.warn":
                warnings.append(params)
                reply = {"type": "response", "v": 2, "id": rid, "result": None}
            elif method == "file.read":
                offset = params.get("offset") or 0
                length = params.get("length") or 0
                data = contents.get(params.get("file_id"), b"")
                reply = {"type": "response", "v": 2, "id": rid,
                         "result": data[offset:offset + length]}
            elif method == "file.release":
                reply = {"type": "response", "v": 2, "id": rid, "result": None}
            else:
                reply = {"type": "response", "v": 2, "id": rid,
                         "error": {"code": "METHOD_NOT_FOUND", "message": method}}
            write_frame(host_out, reply)
            continue


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    host_binary = sys.argv[1]
    library = os.path.abspath(sys.argv[2])
    paths = sys.argv[3:]
    analyzer = DEFAULT_ANALYZER
    if paths[-1] == "winregevidence":
        analyzer = paths.pop()
    options = {}
    if os.environ.get("DRIVE_OPTIONS"):
        options = json.loads(os.environ["DRIVE_OPTIONS"])
    packages = []
    for path in paths:
        with open(path, "rb") as handle:
            packages.append((path, handle.read()))

    log_path = os.path.join(tempfile.gettempdir(), "lc-apkanalyzer-loader.err")
    with open(log_path, "wb") as log:
        watchdog = threading.Timer(300, lambda: os._exit(3))
        watchdog.daemon = True
        watchdog.start()
        proc = subprocess.Popen(
            [host_binary, "--library", library],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
        )
        outcome = {}
        try:
            outcome = serve(proc.stdout, proc.stdin, analyzer, packages, options)
        finally:
            try:
                write_frame(proc.stdin, {"type": "request", "v": 2, "id": 4,
                                         "method": "plugin.shutdown", "params": {}})
                proc.wait(timeout=10)
            except Exception:
                proc.kill()
            watchdog.cancel()

    if outcome.get("error"):
        print("run.start failed ->", json.dumps(outcome["error"], ensure_ascii=False))
    else:
        print("summary  ->", (outcome.get("result") or {}).get("summary"))
    counts = collections.Counter(record.get("type") for record in outcome.get("records", []))
    print("records  ->", dict(sorted(counts.items())))
    for record in outcome.get("records", []):
        if record.get("type") != "apk.info":
            continue
        print("info     ->", record.get("values"))
    print("warnings ->", outcome.get("warnings"))
    try:
        proc.stdin.close()
    except OSError:
        pass
    stderr_text = open(log_path, "rb").read().decode(errors="replace").strip()
    for line in stderr_text.splitlines()[:10]:
        print("log      ->", line)
    print("exit code:", proc.returncode)
    return 0 if proc.returncode == 0 and not outcome.get("error") else 1


if __name__ == "__main__":
    sys.exit(main())
