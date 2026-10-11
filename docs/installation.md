# Native Linux installation

## Current availability

The supported deployment shape is a native Linux GNU binary managed by the
systemd system manager. The release qualification targets are x86_64 and
aarch64 with glibc 2.17 or newer. The host needs systemd, kernel WireGuard,
`nftables`, and the Linux capabilities required to manage network interfaces.
The release installer itself is a small Rust binary; Rust, Cargo, Python,
Node, and Docker are not runtime requirements.

Releases are checksums-only by maintainer decision: GitHub TLS delivery
plus published SHA-256 digests, with no detached signatures and no
production trust key. `update check` and `update run` fail closed
permanently; every release requires a fresh install. Do not treat a
fixture-signed artifact or a local candidate as a release.

## Install a local candidate

The current native install command accepts a local executable. It requires
root and a running systemd system manager and does not authenticate a download
or invoke `sudo` itself. Obtain and verify the candidate through a trusted
channel before running it:

```sh
sudo ./wg-basic system install --candidate ./wg-basic
sudo ./wg-basic system status
```

Install creates the `wg-basic` and `wg-basic-netd` service identities, installs
the canonical binary and hardened service units, initializes state through the
management service, then starts the services. The default management endpoint
is loopback on port 8000. Set the initial administrator password from a
terminal using stdin under the management UID; never place it in command-line
arguments or environment variables:

```sh
printf '%s\n' 'a strong administrator password' | \
  sudo -u wg-basic /usr/local/bin/wg-basic admin set-password \
    --password-stdin --state /var/lib/wg-basic/state.db
```

Use the management UI to create the server and client, then verify client
traffic before exposing the management interface through a separately
configured TLS proxy.

The install receipt and service definitions are root-owned. `system status`
checks their ownership and exact definitions. Install refuses foreign or
modified destinations rather than replacing them.

## Preserve state when uninstalling

Default uninstall stops the services and removes only verified wg-basic
service, sysusers, receipt, and executable files:

```sh
sudo wg-basic system uninstall
```

The database at `/var/lib/wg-basic/state.db` and the service identities remain
in place. Keeping the `wg-basic` identity preserves meaningful ownership of
the secret-bearing database. Reinstall with the same command above to reuse
that database and its VPN identity. Back up state before maintenance using the
procedure in [State backup and restore](state-backup-restore.md).

Uninstall refuses modified or foreign files/units and does not delete the
state. It is not a network teardown operation. To deliberately remove product
state, first disable networking and verify convergence, then use
`state purge --confirm-installation-id ...` as documented in the
[operations runbook](operations-runbook.md). Once the guarded purge has
removed the database, run `system uninstall` to remove the remaining system
files. Keep independent backups until the appliance is no longer needed.

## Authenticity and bootstrap trust

`release/eggpack/install.sh --version X.Y.Z` is a **lower-assurance convenience
path**. It downloads and runs the exact-version installer from GitHub over
HTTPS. It does not independently authenticate that bootstrap or its manifest.
The wrapper prints this trust limitation before downloading. Its
`--candidate --sha256 --size` mode checks file integrity against the supplied
values; those values are trustworthy only after they have been compared
against the release notes, and both travel over the same TLS channel, so this
is integrity against corruption — not authenticity against a compromised
publisher. The wrapper verifies no signatures because releases carry none.

No production key or signed release exists, by maintainer decision (see
[release signing](release-signing.md)). There is therefore no
independently distributed trust key and no signed high-assurance path;
the strongest available procedure is the checksums-and-consistency
verification below. Its anchor is the GitHub TLS delivery channel plus the
published digests: it detects corruption and mix-ups, but a compromised
publisher account would defeat it. Use it from a trusted Linux x86_64 or
aarch64 machine:

```sh
set -eu
VERSION='X.Y.Z'
case "$VERSION" in ''|*[!0-9.]*|.*|*.|*..*) exit 2;; esac
case "$VERSION" in *.*.*.*) exit 2;; esac
VERSION_REST="${VERSION#*.}"
VERSION_PATCH="${VERSION_REST#*.}"
case "$VERSION" in 0[0-9]*.*|*\.0[0-9]*.*|*.*\.0[0-9]*) exit 2;; esac
case "$VERSION_PATCH" in *.*) exit 2;; esac
TAG="v$VERSION"
BASE="https://github.com/dbowm91/wg-basic/releases/download/$TAG"
WORK="$(mktemp -d)"
chmod 700 "$WORK"
STAGE=
cleanup() { if [ -n "$STAGE" ]; then sudo rm -rf -- "$STAGE"; fi; rm -rf -- "$WORK"; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --connect-timeout 10 --max-time 60 "$BASE/release-manifest.json" \
  -o "$WORK/release-manifest.json"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --connect-timeout 10 --max-time 60 "$BASE/install.sh" -o "$WORK/install.sh"
# No signatures exist to check. Compare the manifest digest bindings against
# the digests published in the release notes before trusting the manifest.
case "$(uname -m)" in x86_64) TARGET=x86_64-unknown-linux-gnu;; aarch64) TARGET=aarch64-unknown-linux-gnu;; *) exit 2;; esac
jq -e --arg version "$VERSION" \
  '.schema_version == 1 and .product_id == "wg-basic" and .release_id == $version and (.source_revision | test("^[0-9a-f]{40}$"))' \
  "$WORK/release-manifest.json" >/dev/null
test "$(jq -er --arg target "$TARGET" '[.targets[] | select(.target == $target)] | length' "$WORK/release-manifest.json")" = 1
SOURCE_SHA="$(jq -er '.source_revision' "$WORK/release-manifest.json")"
REMOTE_TAG_REFS="$(git ls-remote "https://github.com/dbowm91/wg-basic.git" "refs/tags/$TAG" "refs/tags/$TAG^{}")"
REMOTE_TAG_SHA="$(printf '%s\n' "$REMOTE_TAG_REFS" | awk -v ref="refs/tags/$TAG" '$2 == ref "^{}" {peeled=$1} $2 == ref {direct=$1} END {print peeled ? peeled : direct}')"
test -n "$REMOTE_TAG_SHA" && test "$SOURCE_SHA" = "$REMOTE_TAG_SHA"
git clone --quiet --depth 1 --single-branch --branch "$TAG" \
  https://github.com/dbowm91/wg-basic.git "$WORK/source"
test "$(git -C "$WORK/source" rev-parse HEAD)" = "$SOURCE_SHA"
SOURCE_VERSION="$(git -C "$WORK/source" show HEAD:Cargo.toml | awk '
  /^\[package\]$/ { in_package=1; next }
  /^\[/ { in_package=0 }
  in_package && /^version[[:space:]]*=/ { gsub(/"/, "", $3); print $3; exit }
')"
test "$SOURCE_VERSION" = "$VERSION"
ARTIFACT="$(jq -er --arg target "$TARGET" '.targets[] | select(.target == $target) | .form.artifact.name' "$WORK/release-manifest.json")"
SIZE="$(jq -er --arg target "$TARGET" '.targets[] | select(.target == $target) | .form.artifact.size' "$WORK/release-manifest.json")"
SHA256="$(jq -er --arg target "$TARGET" '.targets[] | select(.target == $target) | .form.artifact.sha256' "$WORK/release-manifest.json")"
test "$ARTIFACT" = "wg-basic-$TARGET"
case "$SIZE" in ''|*[!0-9]*) exit 2;; esac
test "$SIZE" -gt 0 && test "$SIZE" -le 104857600
printf '%s' "$SHA256" | grep -Eq '^[0-9a-f]{64}$'
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --connect-timeout 10 --max-time 600 "$BASE/$ARTIFACT" -o "$WORK/wg-basic"
test "$(wc -c < "$WORK/wg-basic" | tr -d '[:space:]')" = "$SIZE"
printf '%s  %s\n' "$SHA256" "$WORK/wg-basic" | sha256sum --check --status
case "$TARGET" in
  x86_64-unknown-linux-gnu) readelf -h "$WORK/wg-basic" | grep -Fq 'Advanced Micro Devices X86-64';;
  aarch64-unknown-linux-gnu) readelf -h "$WORK/wg-basic" | grep -Fq 'AArch64';;
esac
test "$("$WORK/wg-basic" --version)" = "wg-basic $VERSION"
# Stage root-owned copies and verify those exact bytes before root execution.
STAGE="$(sudo mktemp -d /root/wg-basic-verified.XXXXXX)"
sudo install -o root -g root -m 500 "$WORK/install.sh" "$STAGE/install.sh"
sudo install -o root -g root -m 500 "$WORK/wg-basic" "$STAGE/wg-basic"
sudo sh -c 'test "$(wc -c < "$1" | tr -d "[:space:]")" = "$2"' sh "$STAGE/wg-basic" "$SIZE"
printf '%s  %s\n' "$SHA256" "$STAGE/wg-basic" | sudo sha256sum --check --status
sudo sh "$STAGE/install.sh" --version "$VERSION" --candidate "$STAGE/wg-basic" \
  --sha256 "$SHA256" --size "$SIZE"
```

The installer runs only after the manifest consistency checks and the
root-owned digest rechecks above have passed. The candidate is verified
against the manifest and is rechecked by the installer before
`system install`. There is no publisher authentication in this path by
design; fixture signatures do not qualify it further.

For current project status, see the [planning registry](../plans/registry.md).
