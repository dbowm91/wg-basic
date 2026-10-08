#!/usr/bin/env python3
"""Exercise signing receipt identity and full asset inventory checks."""

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
VERIFY = ROOT / "scripts" / "verify-signing-request.py"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="wg-basic-signing-test-") as raw:
        root = Path(raw)
        assets = root / "assets"
        assets.mkdir()
        files = {
            "wg-basic-aarch64-unknown-linux-gnu": b"arm candidate",
            "wg-basic-x86_64-unknown-linux-gnu": b"x64 candidate",
            "install.sh": b"bootstrap wrapper",
            "install-exact.sh": b"generated POSIX bootstrap",
            "install.ps1": b"unsupported host wrapper",
            "install-exact.ps1": b"generated PowerShell bootstrap",
        }
        for name, content in files.items():
            (assets / name).write_bytes(content)
        targets = []
        inventory = []
        for target in ("aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"):
            name = f"wg-basic-{target}"
            content = files[name]
            sha = hashlib.sha256(content).hexdigest()
            targets.append({
                "target": target,
                "form": {
                    "kind": "direct",
                    "artifact": {"name": name, "size": len(content), "sha256": sha},
                    "install": "wg-basic",
                },
            })
            sidecar = f"{sha}  {name}\n".encode("ascii")
            files[f"{name}.sha256"] = sidecar
            (assets / f"{name}.sha256").write_bytes(sidecar)
        manifest = {
            "schema_version": 1,
            "product_id": "wg-basic",
            "release_id": "1.2.3",
            "source_revision": "a" * 40,
            "targets": targets,
        }
        manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode()
        (assets / "release-manifest.json").write_bytes(manifest_bytes)
        files["release-manifest.json"] = manifest_bytes
        inventory = [
            {"name": name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            for name, content in files.items()
        ]
        receipt = {
            "schema_version": 1,
            "owner": "dbowm91",
            "repository": "wg-basic",
            "release_id": "1.2.3",
            "tag": "v1.2.3",
            "source_revision": "a" * 40,
            "draft": True,
            "immutable": False,
            "assets": inventory,
        }
        receipt_path = root / "receipt.json"
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

        def verify() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, str(VERIFY), str(receipt_path), str(assets)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

        if verify().returncode:
            raise RuntimeError("valid signing receipt was rejected")
        (assets / "install.sh").write_bytes(b"tampered")
        if verify().returncode == 0:
            raise RuntimeError("tampered installer bytes were accepted")
        print("signing request verifier passed identity and tamper checks")


if __name__ == "__main__":
    main()
