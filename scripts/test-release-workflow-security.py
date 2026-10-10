#!/usr/bin/env python3
"""Check generated release workflow input handling and write-job gating."""

import os
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/release-eggpack.yml"
PROVENANCE_WORKFLOW = ROOT / ".github/workflows/release-provenance.yml"


def run_blocks(text: str) -> list[tuple[str, str]]:
    lines = text.splitlines()
    blocks: list[tuple[str, str]] = []
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)run:\s*(.*)$", line)
        if not match:
            continue
        indent = len(match.group(1))
        inline = match.group(2)
        if inline not in {"|", ">", "|-", ">-", "|+", ">+"}:
            blocks.append((inline, line))
            continue
        body = []
        for following in lines[index + 1 :]:
            if following.strip() and len(following) - len(following.lstrip()) <= indent:
                break
            body.append(following)
        blocks.append(("\n".join(body), line))
    return blocks


def main() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    blocks = run_blocks(text)
    if not blocks:
        raise RuntimeError("generated release workflow has no run steps")
    for body, where in blocks:
        if "${{ inputs." in body or "${{ github.event." in body:
            raise RuntimeError(f"untrusted event expression appears in shell body at {where}")

    validator = re.search(
        r"- name: Validate exact-tag source\n"
        r"(?P<step>(?:\s+.*\n)+?)\s+- name:",
        text,
    )
    if not validator:
        raise RuntimeError("generated workflow has no exact-tag validator")
    step = validator.group("step")
    env_match = re.search(r"EGGPACK_RELEASE_TAG:\s*\$\{\{ inputs\.release_tag \}\}", step)
    script_match = re.search(r"\n\s+run: \|\n(?P<script>(?:\s{10,}.*\n)+)", step)
    if not env_match or not script_match:
        raise RuntimeError("tag validator does not receive the dispatch value via env")
    script = "\n".join(line[10:] for line in script_match.group("script").splitlines())

    with tempfile.TemporaryDirectory(prefix="wg-basic-release-tag-guard-") as raw:
        marker = Path(raw) / "executed"
        accepted = subprocess.run(
            ["bash", "-e", "-c", script],
            env={**os.environ, "EGGPACK_RELEASE_TAG": "v1.2.3"},
            capture_output=True,
            text=True,
            check=False,
        )
        if accepted.returncode:
            raise RuntimeError("canonical stable release tag was rejected")
        payload = f"v1.2.3$(touch {marker})"
        rejected = subprocess.run(
            ["bash", "-e", "-c", script],
            env={**os.environ, "EGGPACK_RELEASE_TAG": payload},
            capture_output=True,
            text=True,
            check=False,
        )
        if rejected.returncode == 0 or marker.exists():
            raise RuntimeError("adversarial dispatch input passed or executed")

    if text.count("contents: write") != 1:
        raise RuntimeError("release workflow must have one write-scoped job")
    stage = re.search(r"(?ms)^  stage:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:|\Z)", text)
    if not stage or "needs: aggregate" not in stage.group("body"):
        raise RuntimeError("write-scoped stage is not gated on aggregate")

    provenance = PROVENANCE_WORKFLOW.read_text(encoding="utf-8")
    for body, where in run_blocks(provenance):
        if "${{" in body:
            raise RuntimeError(f"workflow expression appears in provenance shell body at {where}")
    if (
        "workflow_run:" not in provenance
        or "contents: write" in provenance
        or "actions: write" in provenance
        or "run-id: ${{ github.event.workflow_run.id }}" not in provenance
        or "conclusion == 'success'" not in provenance
    ):
        raise RuntimeError("provenance workflow is not a read-only successful-run consumer")
    print("release workflow rejects shell interpolation and gates its sole write job")


if __name__ == "__main__":
    main()
