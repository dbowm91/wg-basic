#!/usr/bin/env python3
"""Verify downloaded draft bytes against Eggpack's immutable staging receipt."""

import hashlib
import json
import re
import sys
from pathlib import Path

EXPECTED_TARGETS = {
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
}


def fail(message: str) -> None:
    raise SystemExit(message)


def digest(path: Path) -> tuple[int, str]:
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            hasher.update(chunk)
    return size, hasher.hexdigest()


def read_bounded(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        fail("signing input is not a bounded regular file")
    return path.read_bytes()


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: verify-signing-request.py RECEIPT.json ASSET_DIRECTORY")
    receipt_path, asset_root = Path(sys.argv[1]), Path(sys.argv[2])
    try:
        receipt = json.loads(read_bounded(receipt_path, 2 * 1024 * 1024))
    except (OSError, UnicodeError, json.JSONDecodeError):
        fail("signing receipt is unreadable or invalid JSON")
    if (
        receipt.get("schema_version") != 1
        or receipt.get("owner") != "dbowm91"
        or receipt.get("repository") != "wg-basic"
        or receipt.get("draft") is not True
        or receipt.get("immutable") is not False
    ):
        fail("signing receipt does not identify the expected draft repository")
    tag = receipt.get("tag", "")
    match = re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag)
    release_id = ".".join(match.groups()) if match else ""
    if not release_id or receipt.get("release_id") != release_id:
        fail("signing receipt tag and manifest release ID disagree")
    revision = receipt.get("source_revision", "")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        fail("signing receipt source revision is invalid")

    inventory = receipt.get("assets")
    if not isinstance(inventory, list) or not inventory or len(inventory) > 1024:
        fail("signing receipt has no asset inventory")
    expected: dict[str, tuple[int, str]] = {}
    for asset in inventory:
        if not isinstance(asset, dict):
            fail("signing receipt asset entry is invalid")
        name = asset.get("name", "")
        size, sha256 = asset.get("size"), asset.get("sha256", "")
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9._+-]{1,200}", name)
            or name in expected
            or not isinstance(size, int)
            or size <= 0
            or not re.fullmatch(r"[0-9a-f]{64}", sha256)
        ):
            fail("signing receipt asset entry is invalid")
        expected[name] = (size, sha256)
    for required in {"release-manifest.json", "install.sh", "install-exact.sh"}:
        if required not in expected:
            fail(f"signing receipt omits {required}")

    if asset_root.is_symlink() or not asset_root.is_dir():
        fail("asset directory must be a real directory")
    observed: dict[str, tuple[int, str]] = {}
    signatures: set[str] = set()
    for path in asset_root.iterdir():
        if path.is_symlink() or not path.is_file():
            fail("asset directory may contain only regular files")
        if path.name in {"release-manifest.json.minisig", "install.sh.minisig"}:
            if path.stat().st_size > 16 * 1024:
                fail("detached signature exceeds its size bound")
            signatures.add(path.name)
            continue
        observed[path.name] = digest(path)
    if signatures and signatures != {"release-manifest.json.minisig", "install.sh.minisig"}:
        fail("draft contains only one of the expected detached signatures")
    if observed != expected:
        fail("downloaded draft bytes do not match the signing receipt inventory")

    try:
        manifest = json.loads(read_bounded(asset_root / "release-manifest.json", 1024 * 1024))
    except (OSError, UnicodeError, json.JSONDecodeError):
        fail("release manifest is unreadable or invalid JSON")
    if (
        manifest.get("product_id") != "wg-basic"
        or manifest.get("release_id") != release_id
        or manifest.get("source_revision") != revision
    ):
        fail("manifest identity differs from the signing receipt")
    targets = manifest.get("targets")
    if (
        not isinstance(targets, list)
        or len(targets) != 2
        or any(not isinstance(row, dict) for row in targets)
        or {row.get("target") for row in targets} != EXPECTED_TARGETS
    ):
        fail("manifest target set does not match the two supported targets")
    for row in targets:
        form = row.get("form", {})
        if not isinstance(form, dict) or not isinstance(form.get("artifact"), dict):
            fail("manifest target form is invalid")
        artifact = form.get("artifact", {})
        target = row["target"]
        name = f"wg-basic-{target}"
        if (
            form.get("kind") != "direct"
            or form.get("install") != "wg-basic"
            or artifact.get("name") != name
            or name not in expected
            or (artifact.get("size"), artifact.get("sha256")) != expected[name]
            or f"{name}.sha256" not in expected
        ):
            fail(f"manifest artifact binding is invalid for {target}")
        sidecar = asset_root / f"{name}.sha256"
        if sidecar.read_bytes() != f"{artifact['sha256']}  {name}\n".encode("ascii"):
            fail(f"checksum sidecar is invalid for {target}")
    print("signing receipt, manifest identity, target inventory, and downloaded bytes match")


if __name__ == "__main__":
    main()
