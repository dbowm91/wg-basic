#!/usr/bin/env python3
"""Exercise the product wrapper without network or host mutation."""

import os
import hashlib
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="wg-basic-installer-test-") as raw:
        root = Path(raw)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        urls = root / "urls"
        installs = root / "installs"
        (fake_bin / "uname").write_text(
            "#!/bin/sh\ncase $1 in -s) echo Linux;; -m) echo x86_64;; esac\n",
            encoding="utf-8",
        )
        (fake_bin / "id").write_text("#!/bin/sh\necho 0\n", encoding="utf-8")
        (fake_bin / "curl").write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "output=\nurl=\n"
            "while [ $# -gt 0 ]; do\n"
            "  if [ \"$1\" = -o ]; then output=$2; shift 2; continue; fi\n"
            "  case $1 in https://*) url=$1;; esac\n"
            "  shift\n"
            "done\n"
            f"printf '%s\\n' \"$url\" >> '{urls}'\n"
            "cat > \"$output\" <<'INSTALLER'\n"
            "#!/bin/sh\n"
            "set -eu\n"
            "cat > \"$1/wg-basic\" <<'CANDIDATE'\n"
            "#!/bin/sh\n"
            "if [ \"$1\" = --version ]; then echo 'wg-basic 1.2.3'; exit 0; fi\n"
            f"printf '%s\\n' \"$*\" >> '{installs}'\n"
            "CANDIDATE\n"
            "chmod 755 \"$1/wg-basic\"\n"
            "INSTALLER\n"
            "chmod 755 \"$output\"\n",
            encoding="utf-8",
        )
        for path in fake_bin.iterdir():
            path.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}:{env['PATH']}"
        result = subprocess.run(
            ["sh", str(ROOT / "release/eggpack/install.sh"), "--version", "1.2.3"],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(f"installer wrapper failed: {result.stderr.strip()}")
        if urls.read_text(encoding="utf-8") != (
            "https://github.com/dbowm91/wg-basic/releases/download/v1.2.3/install-exact.sh\n"
        ):
            raise RuntimeError("installer did not fetch the exact-version HTTPS bootstrap")
        observed = installs.read_text(encoding="utf-8").strip()
        if not observed.startswith("system install --candidate "):
            raise RuntimeError("installer did not delegate to `system install`")

        candidate = root / "preverified-candidate"
        candidate.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = --version ]; then echo 'wg-basic 1.2.3'; exit 0; fi\n"
            f"printf '%s\\n' \"$*\" >> '{installs}'\n",
            encoding="utf-8",
        )
        candidate.chmod(0o755)
        urls.write_text("", encoding="utf-8")
        installs.write_text("", encoding="utf-8")
        result = subprocess.run(
            [
                "sh",
                str(ROOT / "release/eggpack/install.sh"),
                "--version",
                "1.2.3",
                "--candidate",
                str(candidate),
                "--sha256",
                hashlib.sha256(candidate.read_bytes()).hexdigest(),
                "--size",
                str(candidate.stat().st_size),
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(f"preverified installer path failed: {result.stderr.strip()}")
        if urls.read_text(encoding="utf-8"):
            raise RuntimeError("preverified candidate path performed network access")
        if not installs.read_text(encoding="utf-8").strip().startswith(
            "system install --candidate "
        ):
            raise RuntimeError("preverified candidate was not delegated to `system install`")
        print("release installer wrapper passed mocked exact-version delegation")


if __name__ == "__main__":
    main()
