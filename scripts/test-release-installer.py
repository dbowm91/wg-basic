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
        wrapper = root / "install.sh"
        source = (ROOT / "release/eggpack/install.sh").read_text(encoding="utf-8")
        safe_path = "PATH=/usr/sbin:/usr/bin:/sbin:/bin\nexport PATH"
        if safe_path not in source:
            raise RuntimeError("installer does not replace the inherited root PATH")
        fixture_path = f"PATH='{fake_bin}:/usr/bin:/bin'\nexport PATH"
        wrapper.write_text(source.replace(safe_path, fixture_path), encoding="utf-8")
        wrapper.chmod(0o755)
        env = os.environ.copy()
        result = subprocess.run(
            ["sh", str(wrapper), "--version", "1.2.3"],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(f"installer wrapper failed: {result.stderr.strip()}")
        if "LOWER-ASSURANCE" not in result.stderr:
            raise RuntimeError("convenience mode did not disclose its bootstrap trust boundary")
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
        unsafe_tmpdir = root / "unsafe-tmp"
        unsafe_tmpdir.mkdir()
        env["TMPDIR"] = str(unsafe_tmpdir)
        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        size = str(candidate.stat().st_size)

        def run_candidate(path: Path, sha: str = digest, byte_count: str = size):
            return subprocess.run(
                [
                "sh",
                str(wrapper),
                "--version",
                "1.2.3",
                "--candidate",
                str(path),
                "--sha256",
                sha,
                "--size",
                byte_count,
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )

        result = run_candidate(candidate)
        if result.returncode:
            raise RuntimeError(f"preverified installer path failed: {result.stderr.strip()}")
        if urls.read_text(encoding="utf-8"):
            raise RuntimeError("preverified candidate path performed network access")
        if not installs.read_text(encoding="utf-8").strip().startswith(
            "system install --candidate "
        ):
            raise RuntimeError("preverified candidate was not delegated to `system install`")
        if list(unsafe_tmpdir.iterdir()):
            raise RuntimeError("installer used attacker-selected TMPDIR")
        installs.write_text("", encoding="utf-8")
        if run_candidate(candidate, "0" * 64).returncode == 0:
            raise RuntimeError("candidate with a mismatched digest was accepted")
        symlink = root / "candidate-link"
        symlink.symlink_to(candidate)
        if run_candidate(symlink).returncode == 0:
            raise RuntimeError("candidate symlink was accepted")
        hardlink = root / "candidate-hardlink"
        hardlink.hardlink_to(candidate)
        if run_candidate(hardlink).returncode == 0:
            raise RuntimeError("candidate with multiple hard links was accepted")
        if installs.read_text(encoding="utf-8") or urls.read_text(encoding="utf-8"):
            raise RuntimeError("rejected candidate reached install or download")
        print("release installer wrapper passed mocked exact-version delegation")


if __name__ == "__main__":
    main()
