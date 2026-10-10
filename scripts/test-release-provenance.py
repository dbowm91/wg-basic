#!/usr/bin/env python3
"""Exercise release receipt binding and reject malformed run metadata."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "scripts/create-release-provenance.py"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="wg-basic-provenance-test-") as raw:
        root = Path(raw)
        receipt = root / "receipt.json"
        output = root / "provenance.json"
        receipt.write_text(json.dumps({
            "schema_version": 1,
            "owner": "dbowm91",
            "repository": "wg-basic",
            "tag": "v1.2.3",
            "source_revision": "a" * 40,
            "github_release_id": 123,
            "draft": True,
            "assets": [{"name": "wg-basic", "size": 1, "sha256": "b" * 64}],
        }), encoding="utf-8")
        env = {
            **os.environ,
            "WGB_RUN_ID": "37987890305",
            "WGB_RUN_ATTEMPT": "2",
            "WGB_WORKFLOW_REF": "dbowm91/wg-basic/.github/workflows/release-eggpack.yml@main",
            "WGB_WORKFLOW_SHA": "c" * 40,
            "WGB_PROVENANCE_RUN_ID": "37987890400",
            "WGB_PROVENANCE_RUN_ATTEMPT": "1",
            "WGB_PROVENANCE_WORKFLOW_SHA": "d" * 40,
        }
        result = subprocess.run(
            [sys.executable, str(TOOL), str(receipt), str(output)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(f"valid provenance rejected: {result.stderr}")
        bound = json.loads(output.read_text(encoding="utf-8"))
        if (bound["run_id"] != 37987890305 or bound["run_attempt"] != 2
                or bound["provenance_run_id"] != 37987890400
                or bound["provenance_run_attempt"] != 1):
            raise RuntimeError("run identity was not preserved")
        env["WGB_WORKFLOW_SHA"] = "bad"
        result = subprocess.run(
            [sys.executable, str(TOOL), str(receipt), str(output)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            raise RuntimeError("malformed workflow SHA was accepted")
        print("release provenance receipt binding passed")


if __name__ == "__main__":
    main()
