#!/usr/bin/env python3
"""Check generated release workflow input handling and write-job gating."""

import json
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
        r"(?ms)^      - name: Resolve and validate immutable release source\n"
        r"(?P<step>.*?)(?=^      - name:|\Z)",
        text,
    )
    if not validator:
        raise RuntimeError("generated workflow has no pre-checkout tag resolver")
    step = validator.group("step")
    env_match = re.search(
        r"EGGPACK_RELEASE_TAG:\s*\"?\$\{\{ inputs\.release_tag \}\}\"?", step
    )
    script_match = re.search(r"(?m)^        run: (\"(?:\\.|[^\"\\])*\")\s*$", step)
    if not env_match or not script_match:
        raise RuntimeError("tag resolver does not receive the dispatch value via env")
    script = json.loads(script_match.group(1))

    with tempfile.TemporaryDirectory(prefix="wg-basic-fake-git-") as raw:
        temp = Path(raw)
        fake_git = temp / "git"
        fake_git.write_text(
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  check-ref-format|init) exit 0 ;;\n"
            "  ls-remote) shift 3; ref=\"$1\"; peeled=\"$2\"; "
            "printf '%s\\t%s\\n' \"$EGGPACK_FAKE_DIRECT\" \"$ref\"; "
            "if [ -n \"$EGGPACK_FAKE_PEELED\" ]; then "
            "printf '%s\\t%s\\n' \"$EGGPACK_FAKE_PEELED\" \"$peeled\"; fi ;;\n"
            "  --git-dir=*) shift; case \"$1\" in "
            "fetch) exit 0 ;; rev-parse) "
            "printf '%s\\n' \"${EGGPACK_FAKE_COMMIT:-${EGGPACK_FAKE_PEELED:-$EGGPACK_FAKE_DIRECT}}\" ;; "
            "*) exit 99 ;; esac ;;\n"
            "  *) exit 99 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        fake_git.chmod(0o755)
        output = temp / "github-output"
        env = {
            **os.environ,
            "PATH": f"{temp}:{os.environ.get('PATH', '')}",
            "EGGPACK_RELEASE_TAG": "v1.2.3",
            "EGGPACK_FAKE_DIRECT": "b" * 40,
            "EGGPACK_FAKE_PEELED": "a" * 40,
            "GITHUB_TOKEN": "fixture-token",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_REPOSITORY": "owner/repo",
            "RUNNER_TEMP": str(temp),
            "GITHUB_OUTPUT": str(output),
        }
        accepted = subprocess.run(
            ["bash", "-e", "-c", script], env=env, capture_output=True, text=True
        )
        if accepted.returncode or "source_sha=" + "a" * 40 not in output.read_text():
            raise RuntimeError("canonical tag did not resolve to its annotated commit")

        light_env = {**env, "EGGPACK_FAKE_DIRECT": "c" * 40, "EGGPACK_FAKE_PEELED": ""}
        output.write_text("", encoding="utf-8")
        lightweight = subprocess.run(
            ["bash", "-e", "-c", script], env=light_env, capture_output=True, text=True
        )
        if lightweight.returncode or "source_sha=" + "c" * 40 not in output.read_text():
            raise RuntimeError("lightweight tag did not resolve to its commit")

        moved_env = {**light_env, "EGGPACK_FAKE_COMMIT": "d" * 40}
        output.write_text("", encoding="utf-8")
        moved = subprocess.run(
            ["bash", "-e", "-c", script], env=moved_env, capture_output=True, text=True
        )
        if moved.returncode == 0:
            raise RuntimeError("tag resolving to a non-commit object was accepted")

        marker = temp / "executed"
        payload = f"v1.2.3$(touch {marker})"
        rejected = subprocess.run(
            ["bash", "-e", "-c", script],
            env={**env, "EGGPACK_RELEASE_TAG": payload},
            capture_output=True,
            text=True,
            check=False,
        )
        if rejected.returncode == 0 or marker.exists():
            raise RuntimeError("adversarial dispatch input passed or executed")

    if text.count("contents: write") != 1:
        raise RuntimeError("release workflow must have one write-scoped job")
    stage = re.search(r"(?ms)^  stage:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:|\Z)", text)
    if not stage or "needs: [ aggregate, resolve ]" not in stage.group("body"):
        raise RuntimeError("write-scoped stage is not gated on aggregate")
    if 'environment:\n      name: "release-staging"' not in stage.group("body"):
        raise RuntimeError("stage is missing its named approval environment")
    if len(re.findall(r"(?m)^    environment:$", text)) != 1:
        raise RuntimeError("deployment environment must be scoped to stage only")

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
