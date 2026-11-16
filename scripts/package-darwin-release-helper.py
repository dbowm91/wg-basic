#!/usr/bin/env python3
"""Package the Darwin wireguard-go companion next to an Eggpack binary asset.

Eggpack builds and stages ``wg-basic-aarch64-apple-darwin``. The pinned
WireGuard helper is not a Cargo crate, so it is produced here from the
declared build input and emitted as a release-shaped companion asset for
``wg-basic system install --helper``.

This script does not claim notarization, signing, or self-update. It only
builds the helper through ``build-wireguard-go-helper.py`` and copies the
bytes under stable release asset names.

Usage (on Apple silicon / macos-15):

    python3 scripts/package-darwin-release-helper.py --output-dir DIR

Outputs in DIR:

    wireguard-go-aarch64-apple-darwin
    wireguard-go-aarch64-apple-darwin.sha256
    wireguard-go.provenance.json
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILDER = REPO_ROOT / "scripts" / "build-wireguard-go-helper.py"
TARGET = "aarch64-apple-darwin"
ASSET = f"wireguard-go-{TARGET}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="Directory that receives the release-shaped helper assets",
    )
    args = parser.parse_args()
    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="wg-basic-darwin-helper-") as tmp:
        staging = Path(tmp)
        completed = subprocess.run(
            [
                sys.executable,
                str(BUILDER),
                "--output-dir",
                str(staging),
                "--target",
                TARGET,
            ],
            cwd=REPO_ROOT,
            check=False,
        )
        if completed.returncode != 0:
            return completed.returncode

        binary = staging / "wireguard-go"
        digest = staging / "wireguard-go.sha256"
        provenance = staging / "wireguard-go.provenance.json"
        for required in (binary, digest, provenance):
            if not required.is_file():
                print(f"missing builder output: {required.name}", file=sys.stderr)
                return 1

        asset_path = output_dir / ASSET
        shutil.copy2(binary, asset_path)
        # Rewrite the digest line to name the release asset, not the staging path.
        hex_digest = digest.read_text(encoding="utf-8").split()[0]
        (output_dir / f"{ASSET}.sha256").write_text(
            f"{hex_digest}  {ASSET}\n", encoding="utf-8"
        )
        shutil.copy2(provenance, output_dir / "wireguard-go.provenance.json")
        print(f"wrote {asset_path}")
        print(f"wrote {output_dir / f'{ASSET}.sha256'}")
        print(f"wrote {output_dir / 'wireguard-go.provenance.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
