# Native Linux installation

## Current availability

The supported deployment shape is a native Linux GNU binary managed by the
systemd system manager. The release qualification targets are x86_64 and
aarch64 with glibc 2.17 or newer. The host needs systemd, kernel WireGuard,
`nftables`, and the Linux capabilities required to manage network interfaces.
The release installer itself is a small Rust binary; Rust, Cargo, Python,
Node, and Docker are not runtime requirements.

Production release signing and publication are still pending maintainer
provisioning. Do not treat a fixture-signed artifact or a local candidate as a
production release. `update check` and `update run` fail closed until the
production trust key is installed in a reviewed release.

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

No public production bootstrap or signed release is currently available. A
convenience command that downloads and runs an installer script would begin
trust at that downloaded script. A public key embedded in the same unverified
script cannot authenticate the script itself. For a high-assurance future
release, obtain the public key independently, verify the detached signatures
over the release manifest and installer, then execute only the verified
installer. The production key fingerprint and exact release instructions must
be published with the eventual signed release.

For current project status, see the [planning registry](../plans/registry.md).
