#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
BUILD="$ROOT/build"
WASMER=${WASMER:-wasmer}
WAT2WASM=${WAT2WASM:-wat2wasm}
OUT=${OUT:-$ROOT/wasmer-stock-cli-native-proof.rebuilt.webc}
rm -rf "$BUILD"
mkdir -p "$BUILD/fs"

"$WAT2WASM" --enable-threads "$ROOT/src/side.wat" -o "$BUILD/side.base.wasm"
"$WAT2WASM" --enable-threads "$ROOT/src/main.wat" -o "$BUILD/main.base.wasm"

python3 - "$BUILD" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])

def uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            byte |= 0x80
        out.append(byte)
        if not value:
            return bytes(out)

def custom(module, name, data):
    name = name.encode()
    payload = uleb(len(name)) + name + data
    return module + b"\0" + uleb(len(payload)) + payload

def subsection(kind, payload):
    return bytes([kind]) + uleb(len(payload)) + payload

mem_info = subsection(1, b"\0\0\0\0")
side = custom((root / "side.base.wasm").read_bytes(), "dylink.0", mem_info)
for index in range(64):
    unique = custom(side, "private.trigger", index.to_bytes(4, "little"))
    (root / "fs" / f"trigger{index:02}.so").write_bytes(unique)
main = custom((root / "main.base.wasm").read_bytes(), "dylink.0", mem_info)
(root / "main.wasm").write_bytes(main)
PY

cat >"$BUILD/wasmer.toml" <<'EOF'
[package]
name = "private/stock-cli-native-proof"
version = "0.1.0"
description = "Private contained Wasmer security proof"

[[module]]
name = "main"
source = "main.wasm"
abi = "wasi"

[fs]
"/" = "fs"

[[command]]
name = "stock-cli-native-proof"
module = "main"
runner = "wasi"
EOF

rm -f "$OUT"
"$WASMER" package build "$BUILD" -o "$OUT" --quiet
sha256sum "$OUT"
