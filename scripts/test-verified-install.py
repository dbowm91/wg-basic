#!/usr/bin/env python3
"""Guard the documented high-assurance bootstrap sequence and trust labels."""

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    docs = (ROOT / "docs/installation.md").read_text(encoding="utf-8")
    wrapper = (ROOT / "release/eggpack/install.sh").read_text(encoding="utf-8")
    checks = [
        "minisign -Vm \"$WORK/release-manifest.json\"",
        "minisign -Vm \"$WORK/install.sh\"",
        "jq -e --arg version",
        "git ls-remote",
        "git clone --quiet",
        '\"$BASE/$ARTIFACT\"',
        "readelf -h",
        '"$WORK/wg-basic" --version',
        "sudo install -o root -g root -m 500 \"$WORK/install.sh\"",
        "sudo install -o root -g root -m 500 \"$WORK/wg-basic\"",
        "sudo minisign -Vm \"$STAGE/install.sh\"",
        "sudo sha256sum --check --status",
        "sudo sh \"$STAGE/install.sh\"",
    ]
    positions = [docs.find(check) for check in checks]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise RuntimeError("documented installation does not authenticate before root execution")
    if "integrity only" not in wrapper:
        raise RuntimeError("candidate mode does not distinguish integrity from authenticity")
    if "LOWER-ASSURANCE: trusting the HTTPS/GitHub-delivered installer bootstrap." not in wrapper:
        raise RuntimeError("convenience mode does not announce its trust boundary")
    if "PATH=/usr/sbin:/usr/bin:/sbin:/bin" not in wrapper or '"${TMPDIR:-/tmp}"' in wrapper:
        raise RuntimeError("installer relies on inherited PATH or TMPDIR")
    result = subprocess.run(
        ["sh", str(ROOT / "release/eggpack/install.sh"), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode or "lower assurance" not in result.stdout:
        raise RuntimeError("installer help does not disclose convenience-mode assurance")
    print("verified-install order and trust labels passed")


if __name__ == "__main__":
    main()
