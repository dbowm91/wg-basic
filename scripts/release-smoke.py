#!/usr/bin/env python3
"""Native, read-only smoke for the exact Eggpack candidate executable."""

import json
import hashlib
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def run(binary: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), *args], check=False, capture_output=True, text=True, timeout=30
    )


def main() -> int:
    if len(sys.argv) != 2:
        print("expected one candidate path", file=sys.stderr)
        return 2
    binary = Path(sys.argv[1])
    version = run(binary, "--version")
    if version.returncode or not re.fullmatch(
        r"wg-basic [0-9]+\.[0-9]+\.[0-9]+\n?", version.stdout
    ):
        raise RuntimeError("candidate version identity is invalid")
    help_result = run(binary, "--help")
    if help_result.returncode or "Linux-native WireGuard appliance" not in help_result.stdout:
        raise RuntimeError("candidate help smoke failed")

    machine = platform.machine().lower()
    if machine not in {"x86_64", "amd64", "aarch64", "arm64"}:
        raise RuntimeError("qualification host architecture is unsupported")
    header = subprocess.run(
        ["readelf", "-h", str(binary)], check=True, capture_output=True, text=True, timeout=15
    ).stdout
    expected_machine = "AArch64" if machine in {"aarch64", "arm64"} else "Advanced Micro Devices X86-64"
    if expected_machine not in header:
        raise RuntimeError("candidate ELF architecture does not match native host")
    with tempfile.TemporaryDirectory(prefix="wg-basic-release-smoke-") as temporary:
        root = Path(temporary)
        doctor = run(
            binary,
            "doctor",
            "--json",
            "--state",
            str(root / "state.db"),
            "--socket",
            str(root / "netd.sock"),
        )
        if doctor.returncode not in {0, 1, 2}:
            raise RuntimeError("read-only doctor smoke returned an unexpected status")
        report = json.loads(doctor.stdout)
        checks = {check["id"]: check["disposition"] for check in report["checks"]}
        if checks.get("sqlite") != "pass" or checks.get("state") != "warn":
            raise RuntimeError("doctor did not safely classify an absent state fixture")
        if checks.get("netd") != "unknown":
            raise RuntimeError("doctor did not safely classify an absent netd fixture")

    dependencies = subprocess.run(
        ["ldd", str(binary)], check=False, capture_output=True, text=True, timeout=15
    )
    if dependencies.returncode or "not found" in dependencies.stdout:
        raise RuntimeError("candidate dynamic dependencies are unavailable")
    version_info = subprocess.run(
        ["readelf", "--version-info", str(binary)],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    ).stdout
    glibc_versions = [
        tuple(int(part) for part in match.split("."))
        for match in re.findall(r"GLIBC_([0-9]+(?:\.[0-9]+)+)", version_info)
    ]
    if not glibc_versions or max(glibc_versions) > (2, 17):
        raise RuntimeError("candidate requires a glibc symbol newer than the 2.17 floor")
    print(
        "native version/help/doctor passed; "
        f"GLIBC floor 2.17 verified (max {'.'.join(map(str, max(glibc_versions)))}); "
        f"artifact size {binary.stat().st_size}; "
        f"artifact SHA-256 {hashlib.sha256(binary.read_bytes()).hexdigest()}; "
        f"dynamic dependencies: {dependencies.stdout.strip().replace(chr(10), '; ')}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"release smoke failed: {error}", file=sys.stderr)
        raise SystemExit(1)
