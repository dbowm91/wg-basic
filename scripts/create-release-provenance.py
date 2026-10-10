#!/usr/bin/env python3
"""Bind Eggpack's draft receipt to the GitHub Actions invocation metadata."""

import json
import os
import re
import sys
import tempfile
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(message)


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: create-release-provenance.py STAGING_RECEIPT OUTPUT.json")
    receipt_path, output_path = map(Path, sys.argv[1:])
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        fail("staging receipt is unreadable or invalid JSON")
    env = os.environ
    run_id, attempt = env.get("WGB_RUN_ID", ""), env.get("WGB_RUN_ATTEMPT", "")
    workflow_ref, workflow_sha = env.get("WGB_WORKFLOW_REF", ""), env.get("WGB_WORKFLOW_SHA", "")
    provenance_run_id = env.get("WGB_PROVENANCE_RUN_ID", "")
    provenance_attempt = env.get("WGB_PROVENANCE_RUN_ATTEMPT", "")
    provenance_workflow_sha = env.get("WGB_PROVENANCE_WORKFLOW_SHA", "")
    if (
        receipt.get("schema_version") != 1
        or receipt.get("owner") != "dbowm91"
        or receipt.get("repository") != "wg-basic"
        or receipt.get("draft") is not True
        or not re.fullmatch(r"[1-9][0-9]{0,19}", run_id)
        or not re.fullmatch(r"[1-9][0-9]{0,5}", attempt)
        or not re.fullmatch(r"[0-9a-f]{40}", workflow_sha)
        or not re.fullmatch(r"[1-9][0-9]{0,19}", provenance_run_id)
        or not re.fullmatch(r"[1-9][0-9]{0,5}", provenance_attempt)
        or not re.fullmatch(r"[0-9a-f]{40}", provenance_workflow_sha)
        or not re.fullmatch(r"dbowm91/wg-basic/.github/workflows/release-eggpack\.yml@[^\r\n]{1,200}", workflow_ref)
    ):
        fail("staging receipt or GitHub invocation identity is invalid")
    assets = receipt.get("assets")
    if not isinstance(assets, list) or not assets or len(assets) > 1024:
        fail("staging receipt inventory is invalid")
    document = {
        "schema_version": 1,
        "owner": "dbowm91",
        "repository": "wg-basic",
        "tag": receipt.get("tag"),
        "source_revision": receipt.get("source_revision"),
        "github_release_id": receipt.get("github_release_id"),
        "workflow_ref": workflow_ref,
        "workflow_sha": workflow_sha,
        "run_id": int(run_id),
        "run_attempt": int(attempt),
        "provenance_run_id": int(provenance_run_id),
        "provenance_run_attempt": int(provenance_attempt),
        "provenance_workflow_sha": provenance_workflow_sha,
        "assets": assets,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.is_symlink():
        fail("provenance output may not be a symlink")
    encoded = json.dumps(document, sort_keys=True, indent=2) + "\n"
    fd, temporary = tempfile.mkstemp(prefix=".release-provenance-", dir=output_path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output_path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    print("release provenance receipt created")


if __name__ == "__main__":
    main()
