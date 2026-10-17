#!/usr/bin/env python3
"""Pyronix package manager for signed .pxpkg repositories."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import posixpath
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone


ROOT = pathlib.Path(os.environ.get("PYRON_ROOT", "/"))
DB = pathlib.Path(os.environ.get("PYRON_DB_DIR", str(ROOT / "var/lib/pyron")))
REPOS = pathlib.Path(os.environ.get("PYRON_REPOS_FILE", str(ROOT / "etc/pyron/repos.json")))
NAME = re.compile(r"^[a-z0-9][a-z0-9+_.-]{0,127}$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_INDEX = 16 * 1024 * 1024
MAX_PACKAGE = 256 * 1024 * 1024
MAX_FILE = 256 * 1024 * 1024
MAX_UNPACKED = 1024 * 1024 * 1024
PROTECTED = {"etc/pyron/repos.json", "var/lib/pyron"}
TARGET_ARCH = "x86_64"


class PyronError(Exception):
    pass


def fail(message: str) -> None:
    raise PyronError(message)


def unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    """Reject duplicate keys instead of silently trusting the last value."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def root_path(path: str) -> pathlib.Path:
    """Resolve an absolute package path under the real root or a test sysroot."""
    return ROOT / path.lstrip("/")


def atomic_json(path: pathlib.Path, value: object, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
        dirfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def read_json(path: pathlib.Path, description: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_json_object)
    except FileNotFoundError:
        fail(f"{description} is not initialized: {path}")
    except (OSError, UnicodeError, ValueError) as exc:
        fail(f"cannot read {description}: {exc}")
    if not isinstance(value, dict):
        fail(f"invalid {description}: expected a JSON object")
    return value


def dbread() -> dict:
    if not (DB / "installed.json").exists():
        return {}
    packages = read_json(DB / "installed.json", "installed-package database")
    for name, record in packages.items():
        if not NAME.fullmatch(name) or not isinstance(record, dict):
            fail("installed-package database has an invalid record")
        if not isinstance(record.get("files", []), list):
            fail(f"installed-package database has an invalid file list: {name}")
    return packages


def load_repos() -> list[dict]:
    config = read_json(REPOS, "repository configuration")
    repos = config.get("repositories")
    if config.get("format") != 1 or not isinstance(repos, list):
        fail("invalid repository configuration")
    seen = set()
    for repo in repos:
        if not isinstance(repo, dict):
            fail("invalid repository entry")
        rid, url = repo.get("id"), repo.get("url", "")
        parsed = urllib.parse.urlparse(url)
        if not isinstance(rid, str) or not NAME.fullmatch(rid) or rid in seen:
            fail("repository IDs must be unique package-style names")
        if parsed.scheme not in ("https", "file") or not parsed.path:
            fail(f"repository {rid} must use an HTTPS or local file URL")
        if parsed.scheme == "file" and (parsed.netloc not in ("", "localhost") or not parsed.path.startswith("/")):
            fail(f"repository {rid} has an invalid local file URL")
        key_path = repo.get("key_file")
        if not isinstance(key_path, str) or not key_path.startswith("/"):
            fail(f"repository {rid} needs an absolute key_file")
        seen.add(rid)
    return repos


def bounded_get(url: str, limit: int) -> bytes:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("https", "file"):
        fail("repository resources must use HTTPS or file URLs")
    request = urllib.request.Request(url, headers={"User-Agent": "pyron/2"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            final = urllib.parse.urlparse(response.geturl())
            if parsed.scheme == "https" and final.scheme != "https":
                fail("refusing a repository redirect away from HTTPS")
            if final.scheme not in ("https", "file"):
                fail("repository redirected to an unsupported URL scheme")
            data = response.read(limit + 1)
    except PyronError:
        raise
    except Exception as exc:
        fail(f"cannot fetch {url}: {exc}")
    if len(data) > limit:
        fail(f"download exceeds the {limit}-byte limit: {url}")
    return data


@contextmanager
def open_package_archive(path: str):
    """Read .pxpkg with Python zlib, or BusyBox gzip when zlib is omitted."""
    try:
        archive = tarfile.open(path, mode="r:gz")
    except tarfile.CompressionError:
        gzip = root_path("/bin/gzip")
        if not gzip.exists():
            fail("Python gzip support and /bin/gzip are both unavailable")
        with tempfile.TemporaryFile(prefix="pyron-unpacked-") as unpacked:
            result = subprocess.run([str(gzip), "-dc", path], stdout=unpacked,
                                    stderr=subprocess.PIPE, check=False)
            if result.returncode:
                detail = result.stderr.decode("utf-8", "replace").strip()
                fail(f"cannot decompress package archive: {detail or result.returncode}")
            if unpacked.tell() > MAX_UNPACKED:
                fail(f"unpacked package exceeds the {MAX_UNPACKED}-byte safety limit")
            unpacked.seek(0)
            with tarfile.open(fileobj=unpacked, mode="r:") as archive:
                yield archive
    else:
        with archive:
            yield archive


def repo_key(repo: dict) -> bytes:
    path = root_path(repo["key_file"])
    try:
        key = path.read_bytes()
    except OSError as exc:
        fail(f"cannot read trusted key for {repo['id']}: {exc}")
    if not key.startswith(b"-----BEGIN PUBLIC KEY-----") and not key.startswith(b"-----BEGIN RSA PUBLIC KEY-----"):
        fail(f"invalid PEM public key for repository {repo['id']}")
    return key


def validate_record(name: str, record: object, repo: dict) -> dict:
    if not NAME.fullmatch(name) or not isinstance(record, dict):
        fail(f"invalid package record in repository {repo['id']}")
    version = record.get("version")
    archive = record.get("archive")
    digest = record.get("sha256")
    arch = record.get("architecture")
    parsed_archive = urllib.parse.urlparse(archive if isinstance(archive, str) else "")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        fail(f"invalid version for {name}")
    if arch not in ("any", "x86_64"):
        fail(f"unsupported architecture for {name}: {arch}")
    if (not isinstance(archive, str) or not archive or parsed_archive.scheme or parsed_archive.netloc
            or archive.startswith("/") or "\\" in archive
            or any(part in ("", ".", "..") for part in archive.split("/"))):
        fail(f"unsafe archive path for {name}")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        fail(f"invalid SHA-256 for {name}")
    for field in ("dependencies", "conflicts"):
        values = record.get(field, [])
        if (not isinstance(values, list) or any(not isinstance(v, str) or not NAME.fullmatch(v) for v in values)
                or len(values) != len(set(values))):
            fail(f"invalid {field} for {name}")
    if not isinstance(record.get("description", ""), str):
        fail(f"invalid description for {name}")
    return record


def fetch_repo(repo: dict) -> tuple[dict, bytes]:
    base = repo["url"].rstrip("/") + "/"
    raw = bounded_get(urllib.parse.urljoin(base, "index.json"), MAX_INDEX)
    signature = bounded_get(urllib.parse.urljoin(base, "index.json.sig"), 8192)
    key = repo_key(repo)
    with tempfile.TemporaryDirectory(prefix="pyron-index-") as temp:
        directory = pathlib.Path(temp)
        (directory / "index.json").write_bytes(raw)
        (directory / "index.sig").write_bytes(signature)
        (directory / "key.pem").write_bytes(key)
        check = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(directory / "key.pem"),
             "-signature", str(directory / "index.sig"), str(directory / "index.json")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
    if check.returncode:
        fail(f"repository signature verification failed: {repo['id']}")
    try:
        document = json.loads(raw, object_pairs_hook=unique_json_object)
    except (UnicodeError, ValueError) as exc:
        fail(f"invalid repository JSON from {repo['id']}: {exc}")
    packages = document.get("packages") if isinstance(document, dict) else None
    if (not isinstance(document, dict) or document.get("format") != 1
            or document.get("repository") != repo["id"] or not isinstance(packages, dict)):
        fail(f"repository identity or format mismatch: {repo['id']}")
    for name, record in packages.items():
        validate_record(name, record, repo)
    return document, raw


def package_index() -> dict[str, list[tuple[dict, dict]]]:
    result: dict[str, list[tuple[dict, dict]]] = {}
    for repo in load_repos():
        document, _ = fetch_repo(repo)
        for name, record in document["packages"].items():
            if name not in result:
                result[name] = [(record, repo)]
            else:
                result[name].append((record, repo))
    return result


def resolve(roots: list[str], available: dict, installed: dict) -> list[str]:
    ordered: list[str] = []
    active: set[str] = set()
    selected: set[str] = set()

    def visit(name: str) -> None:
        if name in installed or name in selected:
            return
        if name in active:
            fail(f"dependency cycle involving {name}")
        records = available.get(name)
        if not records:
            fail(f"package or dependency unavailable: {name}")
        record = records[0][0]
        active.add(name)
        conflicts = set(record.get("conflicts", []))
        if conflicts.intersection(installed) or conflicts.intersection(selected):
            fail(f"{name} conflicts with an installed or selected package")
        for dependency in record.get("dependencies", []):
            visit(dependency)
        active.remove(name)
        selected.add(name)
        ordered.append(name)

    for root in roots:
        if not isinstance(root, str) or not NAME.fullmatch(root):
            fail(f"invalid package name: {root}")
        visit(root)
    return ordered


def package_path(path: object) -> tuple[str, pathlib.Path]:
    if not isinstance(path, str) or not path.startswith("/") or "\\" in path or "\x00" in path:
        fail(f"package file path must be absolute: {path!r}")
    pure = pathlib.PurePosixPath(path)
    rel = pure.as_posix().lstrip("/")
    if (not rel or any(part in ("", ".", "..") for part in pure.parts[1:])
            or any(ord(ch) < 32 for ch in rel)
            or any(rel == item or rel.startswith(item + "/") for item in PROTECTED)):
        fail(f"unsafe package path: {path}")
    top = pathlib.PurePosixPath(rel).parts[0]
    if top not in {"usr", "opt", "etc", "var"}:
        fail(f"package path outside allowed system areas: {path}")
    destination = root_path("/" + rel)
    current = destination
    while current != ROOT:
        if current.is_symlink():
            fail(f"refusing package path through symlink: {current}")
        current = current.parent
    return rel, destination


def safe_link_target(rel: str, target: object) -> str:
    """Validate a package symlink without following it during installation."""
    if (not isinstance(target, str) or not target or "\\" in target or "\x00" in target
            or any(ord(ch) < 32 for ch in target)):
        fail(f"invalid package symlink target for /{rel}")
    if target.startswith("/"):
        resolved = posixpath.normpath(target).lstrip("/")
    else:
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(rel), target))
    if resolved in ("", ".", "..") or resolved.startswith("../"):
        fail(f"package symlink escapes allowed paths: /{rel} -> {target}")
    top = resolved.split("/", 1)[0]
    if top not in {"usr", "opt", "etc", "var"}:
        fail(f"package symlink target outside allowed system areas: /{rel} -> {target}")
    if any(resolved == item or resolved.startswith(item + "/") for item in PROTECTED):
        fail(f"package symlink targets protected Pyron data: /{rel} -> {target}")
    return target


def installed_entry_matches(path: pathlib.Path, item: dict) -> bool:
    """Check package ownership for regular files and v1 symlink rows."""
    if item.get("type", "file") == "symlink":
        try:
            return path.is_symlink() and os.readlink(path) == item.get("target")
        except OSError:
            return False
    try:
        return (not path.is_symlink()
                and hashlib.sha256(path.read_bytes()).hexdigest() == item.get("sha256"))
    except OSError:
        return False


def load_package(record: dict, repo: dict, name: str) -> tuple[dict, list[dict]]:
    url = urllib.parse.urljoin(repo["url"].rstrip("/") + "/", record["archive"])
    blob = bounded_get(url, MAX_PACKAGE)
    if hashlib.sha256(blob).hexdigest() != record["sha256"]:
        fail(f"archive hash mismatch: {name}")
    with tempfile.NamedTemporaryFile(prefix="pyron-package-", suffix=".pxpkg") as stream:
        stream.write(blob)
        stream.flush()
        try:
            package_archive = open_package_archive(stream.name)
            with package_archive as archive:
                return parse_package_archive(archive, record, name)
        except (tarfile.TarError, OSError) as exc:
            fail(f"invalid package archive {name}: {exc}")


def parse_package_archive(archive: tarfile.TarFile, record: dict, name: str) -> tuple[dict, list[dict]]:
            members = archive.getmembers()
            if len(members) > 10000 or any(not (member.isfile() or member.issym()) for member in members):
                fail(f"package contains unsupported archive entries: {name}")
            member_by_name = {}
            for member in members:
                if member.name in member_by_name or member.name.startswith("/") or ".." in pathlib.PurePosixPath(member.name).parts:
                    fail(f"unsafe or duplicate archive entry in {name}: {member.name}")
                member_by_name[member.name] = member
            metadata_member = member_by_name.get("metadata.json")
            if metadata_member is None or metadata_member.size > 1024 * 1024:
                fail(f"package metadata missing or oversized: {name}")
            try:
                metadata = json.load(archive.extractfile(metadata_member), object_pairs_hook=unique_json_object)
            except (TypeError, UnicodeError, ValueError) as exc:
                fail(f"invalid package metadata for {name}: {exc}")
            if (not isinstance(metadata, dict) or metadata.get("format") != 1 or metadata.get("name") != name
                    or metadata.get("version") != record["version"]
                    or metadata.get("architecture") != record["architecture"]):
                fail(f"package metadata does not match signed index: {name}")
            for field in ("dependencies", "conflicts"):
                if metadata.get(field, []) != record.get(field, []):
                    fail(f"archive/index {field} mismatch: {name}")
            rows = metadata.get("files")
            if not isinstance(rows, list) or not rows:
                fail(f"package has no file manifest: {name}")
            paths = set()
            staged = []
            expected_members = {"metadata.json"}
            for row in rows:
                if not isinstance(row, dict):
                    fail(f"invalid file row in {name}")
                rel, destination = package_path(row.get("path"))
                if rel in paths:
                    fail(f"duplicate installed path in {name}: /{rel}")
                paths.add(rel)
                member_name = "payload/" + rel
                member = member_by_name.get(member_name)
                kind = row.get("type", "file")
                if kind == "symlink":
                    target = safe_link_target(rel, row.get("target"))
                    if member is None or not member.issym() or member.linkname != target:
                        fail(f"missing or mismatched symlink in {name}: /{rel}")
                    digest = hashlib.sha256(target.encode("utf-8")).hexdigest()
                    if row.get("sha256") != digest:
                        fail(f"symlink target hash mismatch: {name} /{rel}")
                    staged.append({"rel": rel, "destination": destination, "type": "symlink",
                                   "target": target, "sha256": digest, "mode": 0o777})
                    expected_members.add(member_name)
                    continue
                if kind != "file":
                    fail(f"unsupported payload type in {name}: /{rel}")
                digest = row.get("sha256")
                if not isinstance(digest, str) or not SHA256.fullmatch(digest):
                    fail(f"invalid file digest in {name}: /{rel}")
                try:
                    mode = int(str(row.get("mode", "644")), 8)
                except ValueError:
                    fail(f"invalid file mode in {name}: /{rel}")
                if mode < 0 or mode > 0o777:
                    fail(f"unsafe file mode in {name}: /{rel}")
                if member is None or not member.isfile() or member.size > MAX_FILE:
                    fail(f"missing or oversized payload in {name}: /{rel}")
                data_stream = archive.extractfile(member)
                if data_stream is None:
                    fail(f"cannot read payload in {name}: /{rel}")
                data = data_stream.read(MAX_FILE + 1)
                if len(data) != member.size or hashlib.sha256(data).hexdigest() != digest:
                    fail(f"payload hash mismatch: {name} /{rel}")
                expected_members.add(member_name)
                staged.append({"rel": rel, "destination": destination, "type": "file",
                               "data": data, "sha256": digest, "mode": mode})
            if set(member_by_name) != expected_members:
                fail(f"package archive has files outside its manifest: {name}")
            return metadata, staged


def require_root() -> None:
    if os.geteuid() != 0:
        fail("this operation changes system files; run it with sudo")


def locked():
    """Context manager that serializes changes to packages and repositories."""
    class Lock:
        def __enter__(self):
            DB.mkdir(parents=True, exist_ok=True)
            self.stream = (DB / "lock").open("a+")
            fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX)
            recover_pending()
            return self

        def __exit__(self, exc_type, exc, tb):
            fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
            self.stream.close()
    return Lock()


def transaction_dir() -> pathlib.Path:
    path = DB / "transactions"
    path.mkdir(parents=True, exist_ok=True)
    return path


def mark_transaction(path: pathlib.Path, journal: dict, state: str) -> None:
    journal["state"] = state
    atomic_json(path, journal)


def record_owns(packages: dict, rel: str) -> bool:
    for record in packages.values():
        for item in record.get("files", []):
            if isinstance(item, dict) and item.get("path") == "/" + rel:
                return True
            if isinstance(item, str) and item == rel:
                return True
    return False


def remove_empty_dirs(directories: list[str]) -> None:
    for rel in sorted(set(directories), key=lambda item: item.count("/"), reverse=True):
        try:
            path = root_path("/" + rel)
            if not path.is_symlink():
                path.rmdir()
        except OSError:
            pass


def recover_pending() -> None:
    directory = DB / "transactions"
    if not directory.is_dir():
        return
    for path in sorted(directory.glob("*.json")):
        journal = read_json(path, "transaction journal")
        if journal.get("state") != "pending":
            continue
        action = journal.get("action")
        packages = dbread()
        if action == "install":
            names = journal.get("package_names", [])
            committed = bool(names) and all(name in packages for name in names)
            if not committed:
                for name in names:
                    packages.pop(name, None)
                atomic_json(DB / "installed.json", packages)
                dirs = []
                for item in journal.get("files", []):
                    rel = item["path"].lstrip("/")
                    target = root_path(item["path"])
                    if record_owns(packages, rel):
                        continue
                    if installed_entry_matches(target, item):
                        try:
                            target.unlink()
                        except OSError:
                            pass
                for name in names:
                    dirs.extend(packages.get(name, {}).get("directories", []))
                remove_empty_dirs(dirs + journal.get("directories", []))
            mark_transaction(path, journal, "committed" if committed else "rolled-back")
        elif action == "remove":
            names = journal.get("package_names", [])
            directories = []
            for name in names:
                record = packages.get(name, {})
                directories.extend(record.get("directories", []))
            for item in journal.get("files", []):
                target = root_path(item["path"])
                if installed_entry_matches(target, item):
                    try:
                        target.unlink()
                    except FileNotFoundError:
                        pass
            for name in names:
                packages.pop(name, None)
            atomic_json(DB / "installed.json", packages)
            remove_empty_dirs(directories)
            mark_transaction(path, journal, "committed")
        else:
            fail(f"unknown operation in pending transaction journal: {path}")


def install(names: list[str], available: dict, yes: bool) -> None:
    require_root()
    with locked():
        installed = dbread()
        plan = resolve(names, available, installed)
        print("Install plan:", ", ".join(plan) if plan else "already installed")
        if not plan:
            return
        if not yes and input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Cancelled.")
            return

        payloads = []
        claimed = {}
        for name in plan:
            record, repo = available[name][0]
            metadata, files = load_package(record, repo, name)
            package_record = {"version": metadata["version"], "repository": repo["id"],
                              "dependencies": metadata.get("dependencies", []),
                              "files": [], "directories": []}
            for item in files:
                rel = item["rel"]
                if rel in claimed or record_owns(installed, rel):
                    fail(f"package file is already owned: /{rel}")
                if item["destination"].exists() or item["destination"].is_symlink():
                    fail(f"refusing to overwrite a file outside the package transaction: /{rel}")
                claimed[rel] = name
                owned = {"path": "/" + rel, "sha256": item["sha256"],
                         "mode": item["mode"], "type": item["type"]}
                if item["type"] == "symlink":
                    owned["target"] = item["target"]
                package_record["files"].append(owned)
            payloads.append((name, package_record, files))

        journal_path = transaction_dir() / (uuid.uuid4().hex + ".json")
        journal = {"format": 1, "action": "install", "state": "pending",
                   "package_names": plan,
                   "files": [{"path": "/" + item["rel"], "sha256": item["sha256"],
                              "type": item["type"], **({"target": item["target"]}
                                    if item["type"] == "symlink" else {})}
                             for _, _, files in payloads for item in files],
                   "directories": []}
        atomic_json(journal_path, journal)
        updated = dict(installed)
        try:
            for name, package_record, files in payloads:
                for item in files:
                    destination = item["destination"]
                    missing = []
                    parent = destination.parent
                    while parent != ROOT and not parent.exists():
                        missing.append(parent)
                        parent = parent.parent
                    for directory in reversed(missing):
                        directory.mkdir()
                        rel_dir = directory.relative_to(ROOT).as_posix()
                        package_record["directories"].append(rel_dir)
                        journal["directories"].append(rel_dir)
                        atomic_json(journal_path, journal)
                    if item["type"] == "symlink":
                        temp_name = destination.parent / (".pyron-" + uuid.uuid4().hex)
                        try:
                            os.symlink(item["target"], temp_name)
                            os.replace(temp_name, destination)
                        finally:
                            try:
                                temp_name.unlink()
                            except FileNotFoundError:
                                pass
                    else:
                        fd, temp_name = tempfile.mkstemp(prefix=".pyron-", dir=destination.parent)
                        try:
                            with os.fdopen(fd, "wb") as stream:
                                stream.write(item["data"])
                                stream.flush()
                                os.fsync(stream.fileno())
                            os.chmod(temp_name, item["mode"])
                            os.replace(temp_name, destination)
                        finally:
                            try:
                                os.unlink(temp_name)
                            except FileNotFoundError:
                                pass
                updated[name] = package_record
            atomic_json(DB / "installed.json", updated)
            mark_transaction(journal_path, journal, "committed")
        except Exception:
            recover_pending()
            raise
        with (DB / "transactions.log").open("a", encoding="utf-8") as log:
            log.write(json.dumps({"operation": "install", "packages": plan, "result": "committed"}) + "\n")
        print("Installed:", ", ".join(plan))


def remove(name: str, yes: bool) -> None:
    require_root()
    if not NAME.fullmatch(name):
        fail(f"invalid package name: {name}")
    with locked():
        installed = dbread()
        if name not in installed:
            fail(f"package is not installed: {name}")
        dependents = sorted(pkg for pkg, record in installed.items()
                            if pkg != name and name in record.get("dependencies", []))
        if dependents:
            fail(f"cannot remove {name}; required by: {', '.join(dependents)}")
        record = installed[name]
        files = record.get("files", [])
        if not files or any(not isinstance(item, dict) for item in files):
            fail(f"{name} has legacy or incomplete ownership data; refusing unsafe removal")
        for item in files:
            target = root_path(item.get("path", ""))
            try:
                if not installed_entry_matches(target, item):
                    fail(f"installed file was modified; refusing removal: {target}")
            except OSError as exc:
                fail(f"cannot verify installed file {target}: {exc}")
        print("Remove plan:", name, f"({len(files)} files)")
        if not yes and input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Cancelled.")
            return
        journal_path = transaction_dir() / (uuid.uuid4().hex + ".json")
        journal = {"format": 1, "action": "remove", "state": "pending", "package_names": [name],
                   "files": [{key: item[key] for key in ("path", "sha256", "type", "target")
                              if key in item} for item in files]}
        atomic_json(journal_path, journal)
        for item in files:
            root_path(item["path"]).unlink()
        updated = dict(installed)
        updated.pop(name)
        atomic_json(DB / "installed.json", updated)
        remove_empty_dirs(record.get("directories", []))
        mark_transaction(journal_path, journal, "committed")
        with (DB / "transactions.log").open("a", encoding="utf-8") as log:
            log.write(json.dumps({"operation": "remove", "package": name, "result": "committed"}) + "\n")
        print("Removed:", name)


def repo_add(rid: str, url: str, key_file: str) -> None:
    require_root()
    if not NAME.fullmatch(rid):
        fail("repository ID must use lowercase letters, digits, and ._+-")
    key_source = pathlib.Path(key_file)
    try:
        key_bytes = key_source.read_bytes()
    except OSError as exc:
        fail(f"cannot read repository key: {exc}")
    if not key_bytes.startswith(b"-----BEGIN PUBLIC KEY-----") and not key_bytes.startswith(b"-----BEGIN RSA PUBLIC KEY-----"):
        fail("repository key must be a PEM public key")
    new_repo = {"id": rid, "url": url.rstrip("/"), "key_file": str(key_source.resolve())}
    with locked():
        repos = load_repos()
        if any(repo["id"] == rid for repo in repos):
            fail(f"repository already exists: {rid}")
        fetch_repo(new_repo)
        repos.append(new_repo)
        atomic_json(REPOS, {"format": 1, "repositories": repos}, mode=0o644)
    print("Added and verified repository:", rid)


def repo_remove(rid: str) -> None:
    require_root()
    with locked():
        repos = load_repos()
        updated = [repo for repo in repos if repo["id"] != rid]
        if len(updated) == len(repos):
            fail(f"repository not found: {rid}")
        atomic_json(REPOS, {"format": 1, "repositories": updated}, mode=0o644)
    print("Removed repository:", rid)


def init_database() -> None:
    DB.mkdir(parents=True, exist_ok=True)
    database = DB / "installed.json"
    if not database.exists():
        atomic_json(database, {})
    transaction_dir()


def installed_list(packages: dict) -> None:
    if not packages:
        print("No Pyron-managed packages are installed.")
        return
    for name, record in sorted(packages.items()):
        print(f"{name}\t{record.get('version', '?')}")


def available_list(available: dict) -> None:
    if not available:
        print("No packages are published in the configured, verified repositories.")
        return
    for name, records in sorted(available.items()):
        record, repo = records[0]
        print(f"{name}\t{record['version']}\t{repo['id']}\t{record.get('description', '')}")


def base_components() -> list[str]:
    paths = {
        "BusyBox": "/bin/busybox", "Python 3": "/usr/bin/python3", "iproute2": "/sbin/ip",
        "DHCP client": "/sbin/dhcpcd", "OpenSSL CLI": "/usr/bin/openssl",
        "e2fsprogs": "/sbin/e2fsck", "util-linux": "/bin/mount",
    }
    return [name for name, path in paths.items() if root_path(path).exists()]


def main() -> None:
    parser = argparse.ArgumentParser(prog="pyron", description="Pyronix native package manager")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="show database, repositories, and source-built base tools")
    listing = commands.add_parser("list", help="list Pyron-managed packages")
    listing.add_argument("--available", "-a", action="store_true", help="list packages in verified repositories")
    commands.add_parser("update", help="verify repositories and refresh the package index")
    commands.add_parser("self-update", help="apply the installed signed Pyron manager update")
    search = commands.add_parser("search"); search.add_argument("query")
    info = commands.add_parser("info"); info.add_argument("name")
    install_parser = commands.add_parser("install"); install_parser.add_argument("names", nargs="+"); install_parser.add_argument("-y", "--yes", action="store_true")
    remove_parser = commands.add_parser("remove"); remove_parser.add_argument("name"); remove_parser.add_argument("-y", "--yes", action="store_true")
    repositories = commands.add_parser("repo", help="manage trusted package repositories")
    repo_cmd = repositories.add_subparsers(dest="repo_command", required=True)
    repo_cmd.add_parser("list")
    add = repo_cmd.add_parser("add"); add.add_argument("--id", required=True); add.add_argument("--url", required=True); add.add_argument("--key-file", required=True)
    remove_repo = repo_cmd.add_parser("remove"); remove_repo.add_argument("id")
    desktop = commands.add_parser("desktop"); desktop_cmd = desktop.add_subparsers(dest="desktop_command", required=True)
    desktop_cmd.add_parser("list"); desktop_install = desktop_cmd.add_parser("install"); desktop_install.add_argument("name")
    bridge = commands.add_parser("bridge"); bridge.add_argument("query", nargs="?")
    args = parser.parse_args()

    if args.command == "self-update":
        require_root()
        updater = root_path("/usr/bin/pyron-manager-update")
        if not updater.is_file():
            fail("manager update helper is missing; install pyron-manager-update first")
        subprocess.run([str(updater)], check=True)
        return

    if args.command == "status":
        packages = dbread()
        repos = load_repos()
        print(f"Pyron database: {'initialized' if (DB / 'installed.json').is_file() else 'not initialized'}")
        print(f"Target architecture: {TARGET_ARCH}")
        print(f"Installed Pyron packages: {len(packages)}")
        print(f"Configured repositories: {len(repos)}")
        for repo in repos:
            key_path = root_path(repo["key_file"])
            try:
                key_ok = key_path.is_file() and repo_key(repo).startswith(
                    (b"-----BEGIN PUBLIC KEY-----", b"-----BEGIN RSA PUBLIC KEY-----"))
            except PyronError:
                key_ok = False
            print(f"Repository {repo['id']}: {repo['url']} (pinned public key: {'present' if key_ok else 'missing or invalid'})")
        cache_path = DB / "index-cache.json"
        try:
            cache = read_json(cache_path, "repository metadata cache")
            timestamp = cache.get("updated_at")
            if not isinstance(timestamp, str):
                raise ValueError("missing updated_at timestamp")
            updated = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if updated.tzinfo is None:
                raise ValueError("timestamp has no timezone")
            age = max(0, int((datetime.now(timezone.utc) - updated.astimezone(timezone.utc)).total_seconds()))
            if age < 3600:
                age_text = f"{age // 60} minutes old"
            elif age < 86400:
                age_text = f"{age // 3600} hours old"
            else:
                age_text = f"{age // 86400} days old"
            freshness = "stale" if age > 7 * 86400 else "recent"
            print(f"Metadata freshness: {freshness}; last successful update {age_text} ({timestamp})")
        except (PyronError, ValueError, TypeError, OverflowError) as error:
            print(f"Metadata freshness: unknown ({error})")
        print("Source-built base tools:", ", ".join(base_components()) or "none detected")
        return
    if args.command == "list":
        if args.available:
            available_list(package_index())
        else:
            installed_list(dbread())
        return
    if args.command == "repo":
        if args.repo_command == "list":
            repos = load_repos()
            if not repos:
                print("No trusted repositories configured.")
            for repo in repos:
                print(f"{repo['id']}\t{repo['url']}\t{repo['key_file']}")
        elif args.repo_command == "add":
            repo_add(args.id, args.url, args.key_file)
        else:
            repo_remove(args.id)
        return
    if args.command == "remove":
        remove(args.name, args.yes)
        return
    if args.command == "desktop":
        if args.desktop_command == "list":
            available = package_index()
            groups = [name for name in ("gnome", "plasma", "xfce") if name in available]
            print("Available desktop groups:", ", ".join(groups) if groups else "none")
            return
        if args.name not in ("gnome", "plasma", "xfce"):
            fail("supported desktop group names are gnome, plasma, and xfce")
        install([args.name], package_index(), False)
        return
    if args.command == "bridge":
        fail("Bridge catalog unavailable until a signed Pyronix application catalog is published")

    available = package_index()
    if args.command == "update":
        cache = {"format": 1, "updated_at": datetime.now(timezone.utc).isoformat(),
                 "packages": {name: {"record": entries[0][0], "repository": entries[0][1]["id"]}
                              for name, entries in sorted(available.items())}}
        require_root()
        with locked():
            init_database()
            atomic_json(DB / "index-cache.json", cache)
        print(f"Verified package records: {len(available)}")
        return
    if args.command == "search":
        query = args.query.casefold()
        matches = [(name, entries[0][0]) for name, entries in sorted(available.items())
                   if query in (name + " " + entries[0][0].get("description", "")).casefold()]
        if not matches:
            print("No matching packages in verified repositories.")
        for name, record in matches:
            print(f"{name}\t{record['version']}\t{record.get('description', '')}")
        return
    if args.command == "info":
        if args.name not in available:
            fail(f"package not found: {args.name}")
        record, repo = available[args.name][0]
        installed_record = dbread().get(args.name)
        print(json.dumps({**record, "repository": repo["id"],
                          "installed": installed_record is not None,
                          "installed_version": installed_record.get("version") if installed_record else None}, indent=2))
        return
    if args.command == "install":
        install(args.names, available, args.yes)
        return
    parser.error("unsupported command")


if __name__ == "__main__":
    try:
        main()
    except PyronError as error:
        print(f"pyron: {error}", file=sys.stderr)
        raise SystemExit(1)
    except (OSError, KeyError, TypeError, ValueError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"pyron: {error}", file=sys.stderr)
        raise SystemExit(1)
