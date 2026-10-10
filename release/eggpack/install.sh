#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

usage() {
    printf '%s\n' \
        "Usage: $0 --version X.Y.Z [--candidate PATH --sha256 HEX --size BYTES]" \
        'Candidate mode checks integrity only; authenticate the manifest and installer signature before running it.' \
        'Version-only mode trusts the HTTPS/GitHub-delivered bootstrap and is lower assurance.'
}
version=
candidate=
expected_sha256=
expected_size=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; version=$2; shift 2 ;;
        --candidate) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; candidate=$2; shift 2 ;;
        --sha256) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; expected_sha256=$2; shift 2 ;;
        --size) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; expected_size=$2; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done
case "$version" in
    ''|*[!0-9.]*|.*|*.|*..*) printf 'a stable X.Y.Z version is required\n' >&2; exit 2 ;;
esac
old_ifs=$IFS
IFS=.
set -- $version
IFS=$old_ifs
[ "$#" -eq 3 ] || { printf 'a stable X.Y.Z version is required\n' >&2; exit 2; }
for component do
    case "$component" in ''|0[0-9]*|*[!0-9]*) printf 'invalid stable version\n' >&2; exit 2 ;; esac
done
[ "$(uname -s)" = Linux ] || { printf 'wg-basic supports Linux only\n' >&2; exit 2; }
case "$(uname -m)" in x86_64|aarch64) ;; *) printf 'unsupported architecture\n' >&2; exit 2 ;; esac
[ "$(id -u)" -eq 0 ] || { printf 'run this installer as root; it does not invoke sudo\n' >&2; exit 2; }
if [ -n "$candidate" ] || [ -n "$expected_sha256" ] || [ -n "$expected_size" ]; then
    [ -n "$candidate" ] && [ -n "$expected_sha256" ] && [ -n "$expected_size" ] || {
        printf 'candidate, signed-manifest SHA-256, and signed-manifest size are required together\n' >&2
        exit 2
    }
    [ "${#expected_sha256}" -eq 64 ] || { printf 'invalid candidate SHA-256\n' >&2; exit 2; }
    case "$expected_sha256" in *[!0-9a-f]*) printf 'invalid candidate SHA-256\n' >&2; exit 2 ;; esac
    case "$expected_size" in ''|*[!0-9]*) printf 'invalid candidate size\n' >&2; exit 2 ;; esac
    [ -f "$candidate" ] && [ ! -L "$candidate" ] && [ -x "$candidate" ] || {
        printf 'candidate must be a regular executable file, not a symlink\n' >&2
        exit 2
    }
    candidate_links=$(stat -c '%h' -- "$candidate")
    [ "$candidate_links" = 1 ] || {
        printf 'candidate must not have additional hard links\n' >&2
        exit 2
    }
    tmp=$(mktemp -d /tmp/wg-basic-install.XXXXXX) || exit 1
    chmod 700 "$tmp"
    cleanup() { rm -rf "$tmp"; }
    trap cleanup 0
    trap 'exit 1' HUP INT TERM
    cp -- "$candidate" "$tmp/wg-basic"
    chmod 700 "$tmp/wg-basic"
    actual_size=$(wc -c < "$tmp/wg-basic" | tr -d '[:space:]')
    [ "$actual_size" = "$expected_size" ] || { printf 'candidate size mismatch\n' >&2; exit 1; }
    if command -v sha256sum >/dev/null 2>&1; then
        actual_sha256=$(sha256sum "$tmp/wg-basic" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual_sha256=$(shasum -a 256 "$tmp/wg-basic" | awk '{print $1}')
    elif command -v openssl >/dev/null 2>&1; then
        actual_sha256=$(openssl dgst -sha256 "$tmp/wg-basic" | sed 's/^.*= //')
    else
        printf 'sha256sum, shasum, or openssl is required\n' >&2
        exit 2
    fi
    [ "$actual_sha256" = "$expected_sha256" ] || { printf 'candidate SHA-256 mismatch\n' >&2; exit 1; }
    candidate_version=$("$tmp/wg-basic" --version)
    [ "$candidate_version" = "wg-basic $version" ] || {
        printf 'candidate version does not match selected release\n' >&2
        exit 1
    }
    "$tmp/wg-basic" system install --candidate "$tmp/wg-basic"
    exit $?
fi

command -v curl >/dev/null 2>&1 || { printf 'curl is required\n' >&2; exit 2; }
tag="v$version"
url="https://github.com/dbowm91/wg-basic/releases/download/$tag/install-exact.sh"
printf '%s\n' 'LOWER-ASSURANCE: trusting the HTTPS/GitHub-delivered installer bootstrap.' >&2
tmp=$(mktemp -d /tmp/wg-basic-install.XXXXXX) || exit 1
chmod 700 "$tmp"
cleanup() { rm -rf "$tmp"; }
trap cleanup 0
trap 'exit 1' HUP INT TERM
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 10 --max-time 60 --max-filesize 1048576 \
    "$url" -o "$tmp/install-exact.sh"
sh "$tmp/install-exact.sh" "$tmp"
[ -x "$tmp/wg-basic" ] || { printf 'verified release installer did not produce wg-basic\n' >&2; exit 1; }
"$tmp/wg-basic" system install --candidate "$tmp/wg-basic"
