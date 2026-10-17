#!/usr/bin/env python3
"""Safely activate the signed Pyron manager update package."""

from __future__ import annotations

import hashlib
import os
import pathlib
import shutil
import stat
import sys
import tempfile
from datetime import datetime, timezone


MANAGER = pathlib.Path("/usr/lib/pyronix/cli.py")
UPDATED = pathlib.Path("/opt/pyron-manager-update/cli.py")
BACKUPS = pathlib.Path("/var/lib/pyron/manager-backups")
EXPECTED_SHA256 = "223affe2c3cdf59c782d0664690f46f07fea62815a599fe07be18a83534ab0c7"


def digest(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def main() -> int:
    if os.geteuid() != 0:
        print("pyron-manager-update: run with sudo or as root", file=sys.stderr)
        return 1
    if not MANAGER.is_file() or not UPDATED.is_file():
        print("pyron-manager-update: expected manager files are missing", file=sys.stderr)
        return 1
    if digest(UPDATED) != EXPECTED_SHA256:
        print("pyron-manager-update: updated manager checksum mismatch", file=sys.stderr)
        return 1
    try:
        source = UPDATED.read_bytes()
        compile(source, str(MANAGER), "exec")
        original_mode = stat.S_IMODE(MANAGER.stat().st_mode)
        BACKUPS.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = BACKUPS / f"cli.py.{timestamp}.bak"
        shutil.copy2(MANAGER, backup)
        if digest(backup) != digest(MANAGER):
            backup.unlink(missing_ok=True)
            raise OSError("backup verification failed")
        fd, temporary = tempfile.mkstemp(prefix=".cli.py.", dir=MANAGER.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(source)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, original_mode)
            os.replace(temporary, MANAGER)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    except (OSError, SyntaxError) as error:
        print(f"pyron-manager-update: {error}", file=sys.stderr)
        return 1
    print(f"Pyron manager updated. Previous version backed up to {backup}")
    print("The updated per-file package limit is 256 MiB.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
