#!/bin/bash
# Off-host WireGuard peer driver for the Darwin live qualification fixtures.
#
# The C001 qualification drives the *product* half on the macOS host. This
# script drives the *peer* half: a second, independent WireGuard implementation
# — the Linux kernel module, not the same helper the product supervises — on
# another host, reachable from the macOS host.
#
# The fixture never reaches the peer directly; it drives this script, so the
# transport between the two hosts can change without the qualification
# changing. The contract is deliberately small:
#
#   address                            -> the peer's reachable IPv4 address
#   apply <config> <server-v4> <v6>    -> install the config, bring the tunnel up
#   status                             -> the peer's `wg show` dump
#   handshake                          -> the peer's last handshake, unix seconds
#   ping4 <address>                    -> ping the macOS host over the tunnel
#   ping6 <address>                    -> ping the macOS host over the tunnel
#   teardown                           -> bring the tunnel down, drop the config
#
# Required environment:
#   WGB_PEER_SSH_HOST  the peer host
#   WGB_PEER_SSH_USER  the peer account, which must be able to sudo
# Optional environment:
#   WGB_PEER_SSH_KEY   the identity file to use
#   WGB_PEER_IFACE     the peer interface name (default: wgbpeer)
#
# The exported client configuration is rewritten before it is installed: the
# product exports the client's *route policy* as AllowedIPs (a default route),
# which on a real peer would blackhole the peer's own traffic, and it exports a
# DNS line that has no meaning here. The peer installs the same keys with
# AllowedIPs narrowed to the server's tunnel addresses, so the peer keeps its
# own routes and only the tunnel's destination is routed into it.

set -euo pipefail

: "${WGB_PEER_SSH_HOST:?WGB_PEER_SSH_HOST must name the peer host}"
: "${WGB_PEER_SSH_USER:?WGB_PEER_SSH_USER must name the peer account}"

PEER_IFACE="${WGB_PEER_IFACE:-wgbpeer}"
REMOTE_CONFIG="/etc/wireguard/${PEER_IFACE}.conf"

SSH=(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
SCP=(scp -q -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
if [[ -n "${WGB_PEER_SSH_KEY:-}" ]]; then
  SSH+=(-i "${WGB_PEER_SSH_KEY}" -o IdentitiesOnly=yes)
  SCP+=(-i "${WGB_PEER_SSH_KEY}" -o IdentitiesOnly=yes)
fi
TARGET="${WGB_PEER_SSH_USER}@${WGB_PEER_SSH_HOST}"

remote() {
  "${SSH[@]}" "${TARGET}" "$@"
}

command="${1:?a peer subcommand is required}"
shift

case "${command}" in
  address)
    # The address the peer is reachable at, so the macOS host can advertise
    # an endpoint the peer can actually dial.
    remote "ip -4 -o addr show scope global | awk '{print \$4}' | cut -d/ -f1 | head -1"
    ;;
  apply)
    config="${1:?the exported client configuration path is required}"
    server_v4="${2:?the server IPv4 tunnel address is required}"
    server_v6="${3:-}"
    rewritten="$(mktemp)"
    trap 'rm -f "${rewritten}"' EXIT
    awk -v v4="${server_v4}" -v v6="${server_v6}" '
      /^[[:space:]]*DNS[[:space:]]*=/ { next }
      /^[[:space:]]*AllowedIPs[[:space:]]*=/ {
        if (v6 != "") { print "AllowedIPs = " v4 ", " v6 }
        else { print "AllowedIPs = " v4 }
        next
      }
      { print }
    ' "${config}" > "${rewritten}"
    "${SCP[@]}" "${rewritten}" "${TARGET}:/tmp/${PEER_IFACE}.conf"
    remote "sudo install -d -m 700 /etc/wireguard && \
             sudo install -m 600 -o root -g root /tmp/${PEER_IFACE}.conf ${REMOTE_CONFIG} && \
             rm -f /tmp/${PEER_IFACE}.conf && \
             (sudo wg-quick down ${PEER_IFACE} >/dev/null 2>&1 || true) && \
             sudo wg-quick up ${REMOTE_CONFIG}"
    ;;
  status)
    remote "sudo wg show ${PEER_IFACE} dump 2>/dev/null || sudo wg show dump 2>/dev/null || true"
    ;;
  handshake)
    # `wg show <iface> latest-handshakes` prints "<public-key>\t<unix-seconds>".
    remote "sudo wg show ${PEER_IFACE} latest-handshakes 2>/dev/null | awk 'NR==1 {print \$2}'"
    ;;
  ping4)
    address="${1:?the address to ping is required}"
    remote "ping -4 -n -c 3 -W 2 -I ${PEER_IFACE} ${address}"
    ;;
  ping6)
    address="${1:?the address to ping is required}"
    remote "ping -6 -n -c 3 -W 2 -I ${PEER_IFACE} ${address}"
    ;;
  teardown)
    remote "(sudo wg-quick down ${PEER_IFACE} >/dev/null 2>&1 || true) && \
             sudo rm -f ${REMOTE_CONFIG}"
    ;;
  *)
    echo "unknown peer subcommand: ${command}" >&2
    exit 2
    ;;
esac
