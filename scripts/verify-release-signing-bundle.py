#!/usr/bin/env python3
"""Preflight a downloaded draft against source, run, and artifact evidence."""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path


OWNER = "dbowm91"
REPOSITORY = "wg-basic"
WORKFLOW = "Eggpack candidate builds"
ROOT = Path(__file__).resolve().parent.parent


def fail(message: str) -> None:
    raise SystemExit(message)


def command(args: list[str], *, timeout: int = 60) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        fail(f"could not complete required preflight command: {args[0]}")
    if result.returncode:
        fail(f"preflight command failed: {args[0]}")
    return result.stdout


def read_json(path: Path, limit: int = 2 * 1024 * 1024) -> dict:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            fail("preflight input is not a bounded regular file")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        fail("preflight input is unreadable or invalid JSON")
    if not isinstance(value, dict):
        fail("preflight input must be a JSON object")
    return value


def validate_run(run_id: int, attempt: int, expected_sha: str,
                 event: str, workflow_name: str) -> None:
    metadata = read_json_from_text(command([
        "gh", "run", "view", str(run_id), "--repo", f"{OWNER}/{REPOSITORY}",
        "--json", "databaseId,attempt,headSha,headBranch,event,status,conclusion,workflowName",
    ]))
    if (
        metadata.get("databaseId") != run_id
        or metadata.get("attempt") != attempt
        or metadata.get("headSha") != expected_sha
        or metadata.get("event") != event
        or metadata.get("status") != "completed"
        or metadata.get("conclusion") != "success"
        or metadata.get("workflowName") != workflow_name
        or not isinstance(metadata.get("headBranch"), str)
    ):
        fail("GitHub Actions run identity or conclusion does not match the provenance receipt")


def read_json_from_text(text: str) -> dict:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        fail("GitHub CLI returned invalid run metadata")
    if not isinstance(value, dict):
        fail("GitHub CLI run metadata must be a JSON object")
    return value


def validate_tag(tag: str, source_sha: str) -> None:
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag):
        fail("release tag is not canonical stable SemVer")
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        fail("release source revision is invalid")
    refs = command(["git", "ls-remote", f"https://github.com/{OWNER}/{REPOSITORY}.git",
                    f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"])
    direct = peeled = None
    for row in refs.splitlines():
        fields = row.split("\t")
        if len(fields) != 2:
            continue
        if fields[1] == f"refs/tags/{tag}":
            direct = fields[0]
        elif fields[1] == f"refs/tags/{tag}^{{}}":
            peeled = fields[0]
    if (peeled or direct) != source_sha:
        fail("live GitHub tag does not resolve to the staged source revision")


def validate_draft(tag: str, expected_names: set[str]) -> set[str]:
    value = read_json_from_text(command([
        "gh", "release", "view", tag, "--repo", f"{OWNER}/{REPOSITORY}",
        "--json", "tagName,isDraft,assets",
    ]))
    names = [row.get("name") for row in value.get("assets", []) if isinstance(row, dict)]
    allowed = expected_names | {"release-manifest.json.minisig", "install.sh.minisig"}
    if (
        value.get("tagName") != tag
        or value.get("isDraft") is not True
        or len(names) != len(set(names))
        or set(names) - allowed
        or not expected_names.issubset(set(names))
    ):
        fail("live draft tag or asset inventory differs from the approved receipt")
    return set(names)


def digest(path: Path) -> tuple[int, str]:
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            hasher.update(chunk)
    return size, hasher.hexdigest()


def compare_assets(local: Path, live: Path, expected: set[str]) -> None:
    for directory in (local, live):
        if directory.is_symlink() or not directory.is_dir():
            fail("asset directory must be a real directory")
        for path in directory.iterdir():
            if path.is_symlink() or not path.is_file():
                fail("asset directories may contain only regular files")
    if {path.name for path in local.iterdir()} != {path.name for path in live.iterdir()}:
        fail("downloaded local assets differ from the live draft inventory")
    allowed = expected | {"release-manifest.json.minisig", "install.sh.minisig"}
    if {path.name for path in live.iterdir()} - allowed:
        fail("live draft contains an unexpected asset")
    for path in local.iterdir():
        if digest(path) != digest(live / path.name):
            fail("local bytes differ from the freshly downloaded live draft")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("provenance", type=Path)
    parser.add_argument("asset_directory", type=Path)
    parser.add_argument("--public-key", type=Path, required=True,
                        help="independently authenticated Minisign public key")
    args = parser.parse_args()
    receipt = read_json(args.receipt)
    provenance = read_json(args.provenance)
    if (
        provenance.get("schema_version") != 1
        or provenance.get("owner") != OWNER
        or provenance.get("repository") != REPOSITORY
        or provenance.get("tag") != receipt.get("tag")
        or provenance.get("source_revision") != receipt.get("source_revision")
        or provenance.get("assets") != receipt.get("assets")
        or not isinstance(provenance.get("run_id"), int)
        or not isinstance(provenance.get("run_attempt"), int)
        or not isinstance(provenance.get("provenance_run_attempt"), int)
        or not re.fullmatch(r"[0-9a-f]{40}", str(provenance.get("workflow_sha", "")))
        or not re.fullmatch(r"[1-9][0-9]{0,19}", str(provenance.get("provenance_run_id", "")))
        or not re.fullmatch(r"[0-9a-f]{40}", str(provenance.get("provenance_workflow_sha", "")))
        or not re.fullmatch(
            rf"{OWNER}/{REPOSITORY}/\.github/workflows/release-eggpack\.yml@[^\r\n]{{1,200}}",
            str(provenance.get("workflow_ref", "")),
        )
    ):
        fail("run-bound provenance receipt does not match the draft receipt")
    if args.public_key.is_symlink() or not args.public_key.is_file():
        fail("public trust key must be a regular file from an independent trust channel")
    validate_run(provenance["run_id"], provenance["run_attempt"],
                 provenance["workflow_sha"], "workflow_dispatch", WORKFLOW)
    validate_run(provenance["provenance_run_id"], provenance["provenance_run_attempt"],
                 provenance["provenance_workflow_sha"], "workflow_run",
                 "Release provenance receipt")
    validate_tag(receipt.get("tag", ""), receipt.get("source_revision", ""))
    if command(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).strip() != receipt.get("source_revision"):
        fail("local source checkout does not match the staged release revision")
    expected_names = {entry.get("name") for entry in receipt.get("assets", [])
                      if isinstance(entry, dict)}
    if not expected_names or len(expected_names) != len(receipt.get("assets", [])):
        fail("staging asset inventory is invalid")
    draft_names = validate_draft(receipt["tag"], expected_names)
    with tempfile.TemporaryDirectory(prefix="wg-basic-signing-draft-") as raw:
        live_assets = Path(raw)
        command(["gh", "release", "download", receipt["tag"], "--repo",
                 f"{OWNER}/{REPOSITORY}", "--dir", str(live_assets)])
        if {path.name for path in live_assets.iterdir()} != draft_names:
            fail("fresh live draft download differs from the GitHub release inventory")
        compare_assets(args.asset_directory, live_assets, expected_names)
        command([sys.executable, str(ROOT / "scripts/verify-signing-request.py"),
                 str(args.receipt), str(live_assets)])
        asset_root = live_assets
        signatures = {
            "release-manifest.json.minisig": "release-manifest.json",
            "install.sh.minisig": "install.sh",
        }
        present = {name for name in signatures if (asset_root / name).exists()}
        if present and present != set(signatures):
            fail("draft has only one detached signature")
        for signature, message in signatures.items():
            if signature in present:
                command(["minisign", "-Vm", str(asset_root / message), "-x",
                         str(asset_root / signature), "-p", str(args.public_key)])
    try:
        cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        fail("local source Cargo identity is unavailable")
    version = cargo.get("package", {}).get("version")
    if receipt.get("release_id") != version:
        fail("release tag, manifest, and Cargo package version do not agree")
    print("source/run/tag/draft identity and downloaded asset bytes verified")


if __name__ == "__main__":
    main()
