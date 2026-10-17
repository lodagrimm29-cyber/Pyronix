#!/usr/bin/env python3
"""Bootstrap the Pyron manager update when Python lacks its zlib module."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request


BASE = "https://raw.githubusercontent.com/lodagrimm29-cyber/Pyronix/main/"
REPO_ID = "pyronix-community"
PACKAGE = "pyron-manager-update"
KEY = pathlib.Path("/etc/pyron/bootstrap-repository.pem")
DB = pathlib.Path("/var/lib/pyron")
MAX_INDEX = 16 * 1024 * 1024
MAX_PACKAGE = 256 * 1024 * 1024
MAX_UNPACKED = 1024 * 1024 * 1024
EXPECTED_PATHS = {
    "opt/pyron-manager-update/cli.py",
    "opt/pyron-manager-update/apply.py",
    "usr/bin/pyron-manager-update",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def fail(message: str) -> None:
    raise RuntimeError(message)


def fetch(url: str, limit: int) -> bytes:
    if urllib.parse.urlparse(url).scheme != "https":
        fail("refusing a non-HTTPS download")
    request = urllib.request.Request(url, headers={"User-Agent": "pyron-bootstrap/1"})
    with urllib.request.urlopen(request, timeout=45) as response:
        if urllib.parse.urlparse(response.geturl()).scheme != "https":
            fail("refusing a redirect away from HTTPS")
        value = response.read(limit + 1)
    if len(value) > limit:
        fail(f"download exceeds its {limit}-byte limit")
    return value


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_index(raw: bytes, signature: bytes) -> dict:
    if not KEY.is_file():
        fail(f"trusted repository key is missing: {KEY}")
    with tempfile.TemporaryDirectory(prefix="pyron-bootstrap-") as temp:
        directory = pathlib.Path(temp)
        index_path = directory / "index.json"
        sig_path = directory / "index.json.sig"
        index_path.write_bytes(raw)
        sig_path.write_bytes(signature)
        result = subprocess.run(
            ["/usr/bin/openssl", "dgst", "-sha256", "-verify", str(KEY),
             "-signature", str(sig_path), str(index_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
    if result.returncode:
        fail("repository index signature verification failed")
    try:
        document = json.loads(raw)
    except (UnicodeError, ValueError) as error:
        fail(f"invalid repository index: {error}")
    if document.get("format") != 1 or document.get("repository") != REPO_ID:
        fail("repository identity or format mismatch")
    return document


def read_package(blob: bytes, record: dict) -> tuple[dict, list[dict]]:
    if sha(blob) != record.get("sha256"):
        fail("package archive checksum does not match the signed index")
    with tempfile.NamedTemporaryFile(prefix="pyron-bootstrap-", suffix=".pxpkg") as compressed:
        compressed.write(blob)
        compressed.flush()
        with tempfile.TemporaryFile(prefix="pyron-bootstrap-tar-") as unpacked:
            result = subprocess.run(["/bin/gzip", "-dc", compressed.name],
                                    stdout=unpacked, stderr=subprocess.PIPE, check=False)
            if result.returncode:
                detail = result.stderr.decode("utf-8", "replace").strip()
                fail(f"BusyBox gzip could not unpack the package: {detail}")
            if unpacked.tell() > MAX_UNPACKED:
                fail("unpacked package exceeds the 1 GiB safety limit")
            unpacked.seek(0)
            try:
                archive = tarfile.open(fileobj=unpacked, mode="r:")
            except (tarfile.TarError, OSError) as error:
                fail(f"invalid package tar archive: {error}")
            with archive:
                members = archive.getmembers()
                by_name = {member.name: member for member in members}
                if (len(members) != 4 or len(by_name) != len(members)
                        or any(not member.isfile() for member in members)):
                    fail("manager package has unexpected archive entries")
                meta_member = by_name.get("metadata.json")
                if meta_member is None or meta_member.size > 1024 * 1024:
                    fail("manager package metadata is missing or oversized")
                metadata = json.load(archive.extractfile(meta_member))
                if (metadata.get("format") != 1 or metadata.get("name") != PACKAGE
                        or metadata.get("version") != record.get("version")
                        or metadata.get("architecture") != "x86_64"):
                    fail("manager package metadata does not match the signed index")
                rows = metadata.get("files")
                if not isinstance(rows, list) or len(rows) != len(EXPECTED_PATHS):
                    fail("manager package file manifest is invalid")
                files = []
                found = set()
                for row in rows:
                    path = row.get("path", "")
                    if not isinstance(path, str) or not path.startswith("/"):
                        fail("manager package contains an invalid destination")
                    relative = path.lstrip("/")
                    if relative not in EXPECTED_PATHS or relative in found:
                        fail("manager package contains an unexpected destination")
                    found.add(relative)
                    member = by_name.get("payload/" + relative)
                    if member is None or member.size > 16 * 1024 * 1024:
                        fail(f"missing or oversized manager file: {path}")
                    stream = archive.extractfile(member)
                    data = stream.read() if stream else b""
                    digest = row.get("sha256")
                    if not isinstance(digest, str) or not SHA256.fullmatch(digest) or sha(data) != digest:
                        fail(f"manager file checksum mismatch: {path}")
                    mode = int(str(row.get("mode", "644")), 8)
                    if mode < 0 or mode > 0o777:
                        fail(f"unsafe file mode for {path}")
                    files.append({"path": "/" + relative, "relative": relative,
                                  "data": data, "sha256": digest, "mode": mode})
                if found != EXPECTED_PATHS or set(by_name) != {
                        "metadata.json", *("payload/" + item for item in EXPECTED_PATHS)}:
                    fail("manager package contents do not match its manifest")
                return metadata, files


def atomic_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def install(metadata: dict, files: list[dict]) -> None:
    DB.mkdir(parents=True, exist_ok=True)
    with (DB / "lock").open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        installed_path = DB / "installed.json"
        installed = json.loads(installed_path.read_text()) if installed_path.is_file() else {}
        if PACKAGE in installed:
            fail("pyron-manager-update is already installed; run sudo pyron self-update")
        if any((pathlib.Path("/") / item["relative"]).exists()
               or (pathlib.Path("/") / item["relative"]).is_symlink() for item in files):
            fail("refusing to overwrite an existing manager-update file")
        made_dirs = []
        written = []
        try:
            for item in files:
                destination = pathlib.Path("/") / item["relative"]
                missing = []
                parent = destination.parent
                while parent != pathlib.Path("/") and not parent.exists():
                    missing.append(parent)
                    parent = parent.parent
                for directory in reversed(missing):
                    directory.mkdir()
                    made_dirs.append(directory)
                fd, temp_name = tempfile.mkstemp(prefix=".pyron-bootstrap-", dir=destination.parent)
                try:
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(item["data"])
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.chmod(temp_name, item["mode"])
                    os.link(temp_name, destination)
                    written.append(destination)
                finally:
                    try:
                        os.unlink(temp_name)
                    except FileNotFoundError:
                        pass
            owned_files = [{"path": item["path"], "sha256": item["sha256"],
                            "mode": item["mode"], "type": "file"} for item in files]
            installed[PACKAGE] = {
                "version": metadata["version"], "repository": REPO_ID,
                "dependencies": [], "files": owned_files,
                "directories": [path.relative_to("/").as_posix() for path in made_dirs],
            }
            atomic_json(installed_path, installed)
        except Exception:
            for path in reversed(written):
                path.unlink(missing_ok=True)
            for path in reversed(made_dirs):
                try:
                    path.rmdir()
                except OSError:
                    pass
            raise
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def main() -> int:
    if os.geteuid() != 0:
        fail("run this bootstrap with sudo or as root")
    raw = fetch(BASE + "index.json", MAX_INDEX)
    signature = fetch(BASE + "index.json.sig", 8192)
    index = verify_index(raw, signature)
    record = index.get("packages", {}).get(PACKAGE)
    if not isinstance(record, dict) or record.get("architecture") != "x86_64":
        fail("signed x86_64 manager update package is not published")
    archive_path = record.get("archive")
    if not isinstance(archive_path, str) or archive_path.startswith("/") or ".." in pathlib.PurePosixPath(archive_path).parts:
        fail("unsafe manager package archive path")
    metadata, files = read_package(fetch(BASE + archive_path, MAX_PACKAGE), record)
    install(metadata, files)
    print("Verified manager package installed. Applying it now...")
    os.execv("/usr/bin/pyron-manager-update", ["/usr/bin/pyron-manager-update"])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, KeyError, TypeError, ValueError, tarfile.TarError,
            subprocess.SubprocessError, RuntimeError) as error:
        print(f"pyron-manager-bootstrap: {error}", file=sys.stderr)
        raise SystemExit(1)
