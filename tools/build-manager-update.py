#!/usr/bin/env python3
"""Build the Pyron self-update package and update the local feed index."""

import hashlib
import json
import pathlib
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "updates" / "pyron"
ARCHIVE = ROOT / "packages" / "pyron-manager-update-1.0.0.pxpkg"
FILES = [
    ("cli.py", "/opt/pyron-manager-update/cli.py", 0o644),
    ("apply.py", "/opt/pyron-manager-update/apply.py", 0o644),
    ("pyron-manager-update", "/usr/bin/pyron-manager-update", 0o755),
]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


rows = []
payloads = []
for source_name, target, mode in FILES:
    data = (SOURCE / source_name).read_bytes()
    rows.append({"path": target, "sha256": sha(data), "mode": format(mode, "o")})
    payloads.append((target.lstrip("/"), data, mode))

metadata = {
    "format": 1,
    "name": "pyron-manager-update",
    "version": "1.0.0",
    "architecture": "x86_64",
    "dependencies": [],
    "conflicts": [],
    "description": "Adds safe Pyron manager self-update and 256 MiB per-file package support",
    "files": rows,
}

with tarfile.open(ARCHIVE, "w:gz", format=tarfile.PAX_FORMAT) as archive:
    meta = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    info = tarfile.TarInfo("metadata.json")
    info.mode = 0o644
    info.size = len(meta)
    archive.addfile(info, __import__("io").BytesIO(meta))
    for name, data, mode in payloads:
        info = tarfile.TarInfo("payload/" + name)
        info.mode = mode
        info.size = len(data)
        archive.addfile(info, __import__("io").BytesIO(data))

blob = ARCHIVE.read_bytes()
index_path = ROOT / "index.json"
index = json.loads(index_path.read_text(encoding="utf-8"))
index["packages"]["pyron-manager-update"] = {
    "architecture": "x86_64",
    "archive": "packages/" + ARCHIVE.name,
    "conflicts": [],
    "dependencies": [],
    "description": metadata["description"],
    "sha256": sha(blob),
    "version": "1.0.0",
}
index_path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"Built {ARCHIVE} ({len(blob)} bytes)")
print(f"Package SHA-256: {sha(blob)}")
print("Updated unsigned index.json; it must be signed before publication.")
