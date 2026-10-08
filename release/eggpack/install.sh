#!/bin/sh
set -eu

usage() { printf 'Usage: %s --version X.Y.Z\n' "$0"; }
version=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; version=$2; shift 2 ;;
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
command -v curl >/dev/null 2>&1 || { printf 'curl is required\n' >&2; exit 2; }

tag="v$version"
url="https://github.com/dbowm91/wg-basic/releases/download/$tag/install-exact.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/wg-basic-install.XXXXXX") || exit 1
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
