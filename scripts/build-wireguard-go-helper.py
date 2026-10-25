#!/usr/bin/env python3
"""Build the pinned wireguard-go helper from the repository's declared build input.

The declaration in ``helper/wireguard-go.provenance.json`` is the single source
of truth for the upstream source, the license, the toolchain, and the target
triples. This script is the only place where the helper is built.

The builder refuses to produce a helper unless every declared property holds:
the clone must be at the declared immutable commit, the checkout must be
clean, the license file must carry the declared marker, and the Go toolchain
must be the declared version. It then writes a provenance receipt recording
what it built, so a qualification run can afterwards be tied to one specific
helper build.

Usage:
    build-wireguard-go-helper.py --output-dir DIR --target aarch64-apple-darwin

Outputs in DIR:
    wireguard-go                      the built helper
    wireguard-go.sha256               "<hex>  <path>", as sha256sum prints it
    wireguard-go.provenance.json      the provenance receipt
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DECLARATION_PATH = REPO_ROOT / "helper" / "wireguard-go.provenance.json"
RECEIPT_NAME = "wireguard-go.provenance.json"
DIGEST_NAME = "wireguard-go.sha256"
BINARY_NAME = "wireguard-go"

# The only triples the declaration may name, and how they map onto Go's
# GOOS/GOARCH pair. A triple that is not in this table is refused rather than
# guessed. Apple silicon is the only Darwin target for this line (ADR-009).
TARGET_TABLE = {
    "aarch64-apple-darwin": ("darwin", "arm64"),
}


class BuildFailure(Exception):
    """A declared property did not hold, or a build step failed."""


def fail(message: str) -> None:
    raise BuildFailure(message)


def run(command, cwd=None, env=None):
    """Runs a command and returns its completed process, failing closed."""
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except OSError as error:
        fail(f"could not run {command[0]}: {error}")
    if completed.returncode != 0:
        fail(
            f"{' '.join(command)} failed with status {completed.returncode}: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    return completed


def load_declaration():
    """Reads and validates the declared build input."""
    try:
        raw = DECLARATION_PATH.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"the build input declaration is unreadable: {error}")
    try:
        declaration = json.loads(raw)
    except json.JSONDecodeError as error:
        fail(f"the build input declaration is not valid JSON: {error}")
    if not isinstance(declaration, dict):
        fail("the build input declaration must be a JSON object")
    if declaration.get("schema_version") != 1:
        fail("the build input declaration has an unsupported schema version")

    source = declaration.get("source")
    if not isinstance(source, dict):
        fail("the declaration has no source object")
    for field in ("url", "tag", "commit"):
        if not isinstance(source.get(field), str) or not source[field].strip():
            fail(f"the declaration has no source {field}")
    commit = source["commit"]
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        fail("the declared source commit must be a full lowercase 40-character object id")

    license_info = declaration.get("license")
    if not isinstance(license_info, dict):
        fail("the declaration has no license object")
    for field in ("spdx", "file", "marker"):
        if not isinstance(license_info.get(field), str) or not license_info[field].strip():
            fail(f"the declaration has no license {field}")

    toolchain = declaration.get("toolchain")
    if not isinstance(toolchain, dict):
        fail("the declaration has no toolchain object")
    go_version = toolchain.get("go_version")
    if not isinstance(go_version, str) or not go_version.strip():
        fail("the declaration has no toolchain go_version")

    targets = declaration.get("targets")
    if not isinstance(targets, list) or not targets:
        fail("the declaration has no targets")
    for target in targets:
        if target not in TARGET_TABLE:
            fail(f"the declared target {target} is not a supported triple")

    build = declaration.get("build")
    if not isinstance(build, dict):
        fail("the declaration has no build object")
    flags = build.get("flags")
    if not isinstance(flags, list) or not all(isinstance(flag, str) for flag in flags):
        fail("the declaration has no build flags list")
    return declaration


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_toolchain(declared_version: str) -> str:
    """Requires the exact declared Go toolchain version."""
    go = shutil.which("go")
    if not go:
        fail("the Go toolchain is not on PATH")
    completed = run([go, "version"])
    reported = completed.stdout.strip()
    # "go version go1.27.1 darwin/arm64"
    parts = reported.split()
    if len(parts) < 3 or parts[0] != "go" or parts[1] != "version" or not parts[2].startswith("go"):
        fail(f"the Go toolchain reported an unexpected version line: {reported}")
    actual = parts[2][2:]
    if actual != declared_version:
        fail(f"the Go toolchain is {actual}, but the declared version is {declared_version}")
    return reported


def clone_source(declaration, destination: Path) -> None:
    """Clones the declared source and proves it is the declared commit."""
    source = declaration["source"]
    run(
        [
            "git",
            "clone",
            "--branch",
            source["tag"],
            "--depth",
            "1",
            source["url"],
            str(destination),
        ]
    )
    resolved = run(["git", "rev-parse", "HEAD^{commit}"], cwd=destination).stdout.strip()
    if resolved != source["commit"]:
        fail(
            f"the clone resolved to commit {resolved}, but the declared commit is {source['commit']}"
        )
    status = run(["git", "status", "--porcelain"], cwd=destination).stdout.strip()
    if status:
        fail("the cloned source is not a clean checkout")


def verify_license(declaration, source_dir: Path) -> dict:
    """Requires the declared license file and marker, and records its digest."""
    license_info = declaration["license"]
    license_path = source_dir / license_info["file"]
    try:
        text = license_path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        fail(f"the declared license file is unreadable: {error}")
    if license_info["marker"] not in text:
        fail("the declared license marker is not present in the license file")
    return {
        "spdx": license_info["spdx"],
        "file": license_info["file"],
        "marker": license_info["marker"],
        "sha256": sha256_file(license_path),
    }


def build_helper(declaration, target: str, source_dir: Path, output: Path) -> list:
    """Builds the helper for one declared target and returns the build flags."""
    goos, goarch = TARGET_TABLE[target]
    flags = list(declaration["build"]["flags"])
    environment = dict(os.environ)
    environment["GOOS"] = goos
    environment["GOARCH"] = goarch
    environment["CGO_ENABLED"] = "0"
    run([shutil.which("go") or "go", "build", *flags, "-o", str(output), "."], cwd=source_dir, env=environment)
    return flags


def build_settings(binary: Path) -> list:
    """The binary's own embedded build settings, including its VCS stamp.

    The first line of `go version -m` names the binary by its full path, which
    on a developer machine would identify that machine. The path is dropped:
    the receipt records the toolchain version, not where the build happened.
    """
    completed = run([shutil.which("go") or "go", "version", "-m", str(binary)])
    settings = []
    for line in completed.stdout.splitlines():
        if not line.strip():
            continue
        if line.startswith("\t"):
            settings.append(line)
            continue
        # "<path>: go1.27.1" -> "go1.27.1"
        _, separator, remainder = line.rpartition(": ")
        settings.append(remainder if separator else line)
    return settings


def write_receipt(path: Path, receipt: dict) -> None:
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, help="where the helper and the receipt are written")
    parser.add_argument("--target", required=True, help="the declared target triple to build")
    arguments = parser.parse_args()

    try:
        declaration = load_declaration()
        if arguments.target not in declaration["targets"]:
            fail(f"{arguments.target} is not one of the declared targets")

        output_dir = Path(arguments.output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        binary = output_dir / BINARY_NAME
        receipt_path = output_dir / RECEIPT_NAME

        go_version_line = verify_toolchain(declaration["toolchain"]["go_version"])
        with tempfile.TemporaryDirectory(prefix="wg-basic-helper-") as workspace:
            source_dir = Path(workspace) / "wireguard-go-src"
            clone_source(declaration, source_dir)
            license_record = verify_license(declaration, source_dir)
            flags = build_helper(declaration, arguments.target, source_dir, binary)

        digest = sha256_file(binary)
        receipt = {
            "schema_version": 1,
            "helper": declaration["name"],
            "target": arguments.target,
            "source": {
                "url": declaration["source"]["url"],
                "tag": declaration["source"]["tag"],
                "commit": declaration["source"]["commit"],
            },
            "license": license_record,
            "toolchain": {
                "go_version": declaration["toolchain"]["go_version"],
                "reported": go_version_line,
            },
            "build": {
                "flags": flags,
                "settings": build_settings(binary),
            },
            "artifact": {
                "file": BINARY_NAME,
                "sha256": digest,
                "size_bytes": binary.stat().st_size,
            },
            "builder": {
                "script": "scripts/build-wireguard-go-helper.py",
                "declaration": str(DECLARATION_PATH.relative_to(REPO_ROOT)),
                "run_id": os.environ.get("GITHUB_RUN_ID", ""),
                "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
                "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF", ""),
                "workflow_sha": os.environ.get("GITHUB_WORKFLOW_SHA", ""),
            },
        }
        write_receipt(receipt_path, receipt)
        (output_dir / DIGEST_NAME).write_text(f"{digest}  {binary}\n", encoding="utf-8")
    except BuildFailure as failure:
        print(f"helper build refused: {failure}", file=sys.stderr)
        return 1

    print(f"built {BINARY_NAME} for {arguments.target}")
    print(f"sha256: {receipt['artifact']['sha256']}")
    print(f"receipt: {receipt_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
