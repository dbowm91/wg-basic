#!/usr/bin/env python3
"""Qualify release-smoke identity checks with isolated command fixtures."""

import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SMOKE = ROOT / "scripts" / "release-smoke.py"


def write_executable(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o755)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="wg-basic-release-smoke-test-") as raw:
        root = Path(raw)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        runtime = root / "eggpack-runtime"
        runtime.mkdir()
        candidate = root / "candidate"
        write_executable(
            candidate,
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  --version) echo \"wg-basic ${CANDIDATE_VERSION:-1.2.3}\";;\n"
            "  --help) echo 'Linux-native WireGuard appliance';;\n"
            "  doctor) echo '{\"checks\":[{\"id\":\"sqlite\",\"disposition\":\"pass\"},{\"id\":\"state\",\"disposition\":\"warn\"},{\"id\":\"netd\",\"disposition\":\"unknown\"}]}' ;;\n"
            "esac\n",
        )
        machine = (
            "AArch64"
            if platform.machine().lower() in {"aarch64", "arm64"}
            else "Advanced Micro Devices X86-64"
        )
        write_executable(
            fake_bin / "readelf",
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            f"  -h) echo 'Machine: {machine}';;\n"
            "  --version-info) echo 'Name: GLIBC_2.17';;\n"
            "esac\n",
        )
        write_executable(fake_bin / "ldd", "#!/bin/sh\necho 'libc.so.6 => /lib/libc.so.6'\n")
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}:{env['PATH']}"

        def run(package_version: str, release_id: str, candidate_version: str) -> subprocess.CompletedProcess[str]:
            (root / "Cargo.toml").write_text(
                f'[package]\nname = "wg-basic"\nversion = "{package_version}"\n',
                encoding="utf-8",
            )
            (runtime / "release-plan.json").write_text(
                json.dumps({"release_id": release_id}), encoding="utf-8"
            )
            local_env = env | {"CANDIDATE_VERSION": candidate_version}
            return subprocess.run(
                [sys.executable, str(SMOKE), str(candidate)],
                cwd=root,
                env=local_env,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )

        if run("1.2.3", "1.2.3", "1.2.3").returncode:
            raise RuntimeError("matching candidate and Eggpack identity were rejected")
        if run("1.2.3", "1.2.4", "1.2.3").returncode == 0:
            raise RuntimeError("manifest identity mismatch was accepted")
        if run("1.2.3", "1.2.3", "1.2.4").returncode == 0:
            raise RuntimeError("candidate version mismatch was accepted")
        print("release smoke passed matching and mismatch identity cases")


if __name__ == "__main__":
    main()
