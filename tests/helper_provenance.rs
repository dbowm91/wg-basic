//! The declared helper build input cannot drift (C008).
//!
//! The Darwin dataplane helper is built from a declared build input: the
//! upstream source, an immutable commit, a license, a Go toolchain version,
//! and the target triples. This suite pins the properties that a build
//! cannot check for itself, and it pins that there is exactly **one**
//! declaration and exactly **one** builder:
//!
//! - the declaration is well formed, and every value in it is pinned;
//! - the builder reads the declaration instead of naming the upstream
//!   source itself;
//! - the qualification workflow builds the helper through that builder and
//!   contains no second copy of the source.

use std::collections::BTreeSet;

/// The declared build input.
const DECLARATION: &str = include_str!("../helper/wireguard-go.provenance.json");
/// The one builder.
const BUILDER: &str = include_str!("../scripts/build-wireguard-go-helper.py");
/// The workflow that qualifies the helper on both architectures.
const WORKFLOW: &str = include_str!("../.github/workflows/macos-qualification.yml");

/// A minimal reader for the declaration. The suite asserts on the file's
/// text, so it does not need a JSON parser dependency.
fn declaration_value(key: &str) -> String {
    let needle = format!("\"{key}\"");
    let start = DECLARATION
        .find(&needle)
        .unwrap_or_else(|| panic!("the declaration must contain {needle}"));
    let after = &DECLARATION[start + needle.len()..];
    let colon = after
        .find(':')
        .unwrap_or_else(|| panic!("the declaration's {key} must have a value"));
    let value = after[colon + 1..].trim_start();
    let rest = value
        .strip_prefix('"')
        .unwrap_or_else(|| panic!("the declaration's {key} must be a string"));
    let end = rest
        .find('"')
        .unwrap_or_else(|| panic!("the declaration's {key} must be a closed string"));
    rest[..end].to_string()
}

#[test]
fn the_declaration_pins_the_upstream_source_immutably() {
    assert!(
        DECLARATION.contains("\"schema_version\": 1"),
        "the declaration must carry the supported schema version"
    );
    assert_eq!(
        declaration_value("url"),
        "https://github.com/WireGuard/wireguard-go",
        "the upstream source must be the canonical repository"
    );
    let tag = declaration_value("tag");
    assert!(
        !tag.is_empty() && tag.chars().all(|c| c.is_ascii_digit() || c == '.'),
        "the declared tag must be a dotted release tag, got {tag}"
    );
    let commit = declaration_value("commit");
    assert_eq!(
        commit.len(),
        40,
        "the declared commit must be a full object id, not an abbreviation"
    );
    assert!(
        commit
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
        "the declared commit must be lowercase hexadecimal, got {commit}"
    );
}

#[test]
fn the_declaration_pins_the_license_and_the_toolchain() {
    assert_eq!(declaration_value("spdx"), "MIT");
    assert_eq!(declaration_value("file"), "LICENSE");
    assert_eq!(
        declaration_value("marker"),
        "Permission is hereby granted, free of charge",
        "the declared license marker must be the MIT grant"
    );
    let go_version = declaration_value("go_version");
    assert_eq!(
        go_version.split('.').count(),
        3,
        "the Go toolchain must be pinned to a full version, got {go_version}"
    );
    assert!(
        !go_version.contains("latest") && !go_version.contains('+'),
        "the Go toolchain must be a fixed release, got {go_version}"
    );
}

#[test]
fn the_declaration_names_exactly_the_two_darwin_targets() {
    let targets: Vec<&str> = DECLARATION
        .lines()
        .skip_while(|line| !line.contains("\"targets\""))
        .skip(1)
        .take_while(|line| !line.contains("]"))
        .filter_map(|line| {
            let trimmed = line.trim().trim_end_matches(',');
            trimmed
                .strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'))
        })
        .collect();
    let unique: BTreeSet<&&str> = targets.iter().collect();
    assert_eq!(
        unique.len(),
        targets.len(),
        "the declared targets must not repeat"
    );
    assert_eq!(
        targets,
        vec!["aarch64-apple-darwin", "x86_64-apple-darwin"],
        "the declared targets must be the two Darwin triples and nothing else"
    );
}

#[test]
fn the_builder_reads_the_declaration_and_names_no_source_of_its_own() {
    assert!(
        BUILDER.contains("wireguard-go.provenance.json"),
        "the builder must read the declared build input"
    );
    assert!(
        !BUILDER.contains("github.com/WireGuard"),
        "the builder must not name the upstream source: the declaration is the only place that does"
    );
    assert!(
        !BUILDER.contains("0.0.20250522") && !BUILDER.contains("f333402b"),
        "the builder must not pin the source itself: the declaration is the only place that does"
    );
}

#[test]
fn the_builder_refuses_a_mismatched_source_license_or_toolchain() {
    for required in [
        "rev-parse",
        "HEAD^{commit}",
        "the declared commit is",
        "the declared license marker is not present",
        "but the declared version is",
        "the cloned source is not a clean checkout",
    ] {
        assert!(
            BUILDER.contains(required),
            "the builder must refuse a mismatched build input: {required}"
        );
    }
}

#[test]
fn the_builder_records_the_provenance_evidence() {
    for required in [
        "\"source\"",
        "\"commit\"",
        "\"license\"",
        "\"spdx\"",
        "\"toolchain\"",
        "\"go_version\"",
        "\"target\"",
        "\"flags\"",
        "\"settings\"",
        "\"sha256\"",
    ] {
        assert!(
            BUILDER.contains(required),
            "the builder must record {required} in the provenance receipt"
        );
    }
    assert!(
        BUILDER.contains("\"version\", \"-m\""),
        "the builder must record the binary's own embedded build settings, which carry the VCS stamp"
    );
}

#[test]
fn the_workflow_builds_the_helper_through_the_one_builder() {
    assert!(
        WORKFLOW.contains("build-wireguard-go-helper.py"),
        "the qualification workflow must build the helper through the declared builder"
    );
    assert!(
        !WORKFLOW.contains("git clone"),
        "the qualification workflow must not carry its own copy of the helper source"
    );
    assert!(
        !WORKFLOW.contains("github.com/WireGuard"),
        "the qualification workflow must not name the upstream source: the declaration is the only place that does"
    );
    assert!(
        WORKFLOW.contains("wireguard-go.provenance.json"),
        "the qualification workflow must keep the provenance receipt"
    );
}
