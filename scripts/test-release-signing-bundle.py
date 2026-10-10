#!/usr/bin/env python3
"""Exercise signing-bundle identity checks without GitHub or key material."""

import importlib.util
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "release_signing_bundle", ROOT / "scripts/verify-release-signing-bundle.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def main() -> None:
    response = {
        "databaseId": 37987890305,
        "attempt": 2,
        "headSha": "a" * 40,
        "headBranch": "main",
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "workflowName": "Eggpack candidate builds",
    }
    with patch.object(MODULE, "command", return_value=__import__("json").dumps(response)):
        MODULE.validate_run(37987890305, 2, "a" * 40, "workflow_dispatch", MODULE.WORKFLOW)
    response["conclusion"] = "failure"
    with patch.object(MODULE, "command", return_value=__import__("json").dumps(response)):
        try:
            MODULE.validate_run(37987890305, 2, "a" * 40, "workflow_dispatch", MODULE.WORKFLOW)
        except SystemExit:
            pass
        else:
            raise RuntimeError("failed GitHub run was accepted")

    ref_output = f"{'b' * 40}\trefs/tags/v1.2.3\n{'c' * 40}\trefs/tags/v1.2.3^{{}}\n"
    with patch.object(MODULE, "command", return_value=ref_output):
        MODULE.validate_tag("v1.2.3", "c" * 40)
    with patch.object(MODULE, "command", return_value=ref_output):
        try:
            MODULE.validate_tag("v1.2.3", "a" * 40)
        except SystemExit:
            pass
        else:
            raise RuntimeError("moved-tag mismatch was accepted")
    print("release signing bundle run and tag rejection checks passed")


if __name__ == "__main__":
    main()
