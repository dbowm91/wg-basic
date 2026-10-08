#!/usr/bin/env python3
"""Derive Eggpack's static release workflow shape from release inputs."""

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / "release" / "eggpack"
ALIASES = ["linux-x64", "linux-arm64"]


def main() -> None:
    with (RELEASE / "pack.toml").open("rb") as stream:
        pack = tomllib.load(stream)
    with (RELEASE / "build-bindings.toml").open("rb") as stream:
        build = tomllib.load(stream)
    with (RELEASE / "qualification-bindings.toml").open("rb") as stream:
        qualification = tomllib.load(stream)
    with (RELEASE / "consumer-validators.json").open(encoding="utf-8") as stream:
        validators = json.load(stream)

    targets = []
    for row in pack["targets"]:
        target = row["target"]
        if target not in build["targets"] or target not in validators:
            raise SystemExit(f"producer inputs do not cover {target}")
        targets.append({key: row[key] for key in (
            "target", "strategy", "host_os", "host_arch", "floor", "qualification", "support"
        )} | {"toolchain": row.get("toolchain", {})})
    targets.sort(key=lambda target: target["target"])
    shape = {
        "schema_version": 1,
        "targets": targets,
        "selected_aliases": ALIASES,
        "build_bindings": build,
        "qualification_bindings": qualification,
        "consumer_validators": validators,
        "staging": {"provider": "git_hub_draft", "tag_source": "dispatch_input", "required": True},
    }
    output = RELEASE / "workflow-shape.json"
    output.write_text(json.dumps(shape, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {output.relative_to(ROOT)} ({len(targets)} targets)")


if __name__ == "__main__":
    main()
