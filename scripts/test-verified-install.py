#!/usr/bin/env python3
"""Guard deployment-status documentation and installer trust labels.

Releases carry no signatures by maintainer decision (R004b waiver), so the
documentation must not present a production install path as supported.
"""

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    docs = (ROOT / "docs/installation.md").read_text(encoding="utf-8")
    wrapper = (ROOT / "release/eggpack/install.sh").read_text(encoding="utf-8")
    required_status = [
        "A supported production installer and system-service setup are not implemented.",
        "Releases are checksums-only.",
        "A SHA-256 match detects corruption, but it does not\nauthenticate a publisher.",
        "no\nsupported self-update path is available.",
        "No macOS release is supported.",
    ]
    missing_status = [statement for statement in required_status if statement not in docs]
    if missing_status:
        raise RuntimeError(
            "deployment documentation omits current status: " + "; ".join(missing_status)
        )
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
    print("deployment status and installer trust-label checks passed")


if __name__ == "__main__":
    main()
