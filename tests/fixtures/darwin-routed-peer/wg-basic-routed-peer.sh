#!/bin/bash
# Routed-LAN WireGuard peer driver for the Darwin C003 qualification.
#
# The C003 leg proves a routed LAN: a Linux-kernel WireGuard peer sends
# traffic through the product's tunnel to an approved downstream LAN prefix,
# and the traffic comes back through the same tunnel. The fixture never
# reaches the peer directly; it drives this script, so the transport between
# the two hosts can change without the qualification changing.
#
# The peer host provides three roles, each isolated so the traffic cannot take
# a shortcut:
#
# - `wgbpeer` namespace: the WireGuard peer, a second and independent
#   implementation (the Linux kernel module, not the helper the product
#   supervises). It holds the client's tunnel address.
# - `wgblan` namespace: the downstream LAN host. It holds the approved
#   downstream address and nothing else, so the only way to reach it is
#   through the tunnel.
# - the root namespace: the upstream router between them. It carries the
#   administrator-installed route back to the tunnel pool, which is the
#   return path the server side cannot observe for itself.
#
# The contract:
#
#   setup                  -> build the topology on the peer host
#   peer-address           -> the peer host's address on the shared network
#   peer-gateway           -> the peer host's default gateway
#   lan-address            -> the downstream LAN host's IPv4 address
#   lan-address6           -> the downstream LAN host's IPv6 address
#   lan-route              -> the LAN host's routing table
#   lan-host-ping <addr>   -> ping from the LAN host to an address
#   lan-host-ping6 <addr>  -> ping from the LAN host to an IPv6 address
#   apply <config> <srv-v4> <srv-v6> <attempted-v4> [attempted-v6]
#                          -> install the config, bring the tunnel up
#   status                 -> the peer's `wg show` dump
#   handshake              -> the peer's last handshake, unix seconds
#   ping-lan <addr>        -> ping from the peer to the downstream host
#   ping-lan6 <addr>       -> ping from the peer to the downstream host (v6)
#   spoof <addr>           -> ping from the peer with a source outside the pool
#   observed-source <addr> -> the IPv4 source the downstream LAN host observed
#                             for the traffic towards <addr>
#   observed-source6 <addr>-> the IPv6 source the downstream LAN host observed
#                             for the traffic towards <addr>
#   teardown               -> bring the tunnel down, drop the config
#
# Required environment:
#   WGB_PEER_SSH_HOST   the peer host
#   WGB_PEER_SSH_USER   the peer account, which must be able to sudo
# Optional environment:
#   WGB_PEER_SSH_KEY    the identity file to use
#   WGB_UPSTREAM_GATEWAY  the upstream router's address on the peer host's
#                         network, which is where the route back to the tunnel
#                         pool points
#   WGB_UPSTREAM_GATEWAY6 the same, for IPv6
#   WGB_LAN_PREFIX      the approved downstream prefix (default 10.20.20.0/24)
#   WGB_LAN_ADDRESS     the LAN host's address (default 10.20.20.2)
#   WGB_LAN_PREFIX6     the approved downstream IPv6 prefix
#   WGB_LAN_ADDRESS6    the LAN host's IPv6 address
#   WGB_TUNNEL_PREFIX   the tunnel pool the return route points at
#   WGB_TUNNEL_PREFIX6  the IPv6 tunnel pool the return route points at

set -euo pipefail

: "${WGB_PEER_SSH_HOST:?WGB_PEER_SSH_HOST must name the peer host}"
: "${WGB_PEER_SSH_USER:?WGB_PEER_SSH_USER must name the peer account}"

PEER_NS="${WGB_PEER_NS:-wgbpeer}"
LAN_NS="${WGB_LAN_NS:-wgblan}"
PEER_IFACE="${WGB_PEER_IFACE:-wgbpeer}"
PEER_LINK_ADDR="${WGB_PEER_LINK_ADDR:-10.30.30.1}"
PEER_ADDR="${WGB_PEER_ADDR:-10.30.30.2}"
PEER_LINK6="${WGB_PEER_LINK6:-fd00:30:30::1}"
PEER_ADDR6="${WGB_PEER_ADDR6:-fd00:30:30::2}"
LAN_GATEWAY_ADDR="${WGB_LAN_GATEWAY_ADDR:-10.20.20.1}"
LAN_ADDR="${WGB_LAN_ADDRESS:-10.20.20.2}"
LAN_GATEWAY6="${WGB_LAN_GATEWAY6:-2001:db8:20::1}"
LAN_ADDR6="${WGB_LAN_ADDRESS6:-2001:db8:20::2}"
LAN_PREFIX="${WGB_LAN_PREFIX:-10.20.20.0/24}"
LAN_PREFIX6="${WGB_LAN_PREFIX6:-2001:db8:20::/64}"
TUNNEL_PREFIX="${WGB_TUNNEL_PREFIX:-10.77.0.0/24}"
TUNNEL_PREFIX6="${WGB_TUNNEL_PREFIX6:-2001:db8:77::/64}"
REMOTE_CONFIG="/etc/wireguard/${PEER_IFACE}.conf"
LAN_IFACE="${WGB_LAN_IFACE:-vethl1}"

# The observation capture.
#
# Only the downstream LAN host can say what arrived. The appliance's own state
# table shows what it translated, and a leg that reads only the appliance's own
# view cannot tell a translated source from an untranslated one. The capture
# therefore runs inside the LAN namespace, on the packets that actually arrived
# there, and records the source address of every ICMP and ICMPv6 packet the
# LAN host received. The capture is a packet-socket reader, so it copies the
# frames without taking them from the stack.
OBSERVED_SCRIPT="/tmp/wg-observed.py"
OBSERVED_LOG="/tmp/wg-observed.log"
OBSERVED_PID="/tmp/wg-observed.pid"

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

# Runs a command as root on the peer host.
#
# The peer account has passwordless sudo for the qualification: the fixture
# runs unattended from inside the test, so it may not wait for a prompt.
#
# The whole command runs under a single `sudo`. A chain joined by `&&` or `;`
# would otherwise lose its privilege after the first link, because the chain
# is split by the remote shell before `sudo` ever sees it.
remote_root() {
  local command="$*"
  local quoted=${command//\'/\'\\\'\'}
  remote "sudo -n sh -c '${quoted}'"
}

# The peer host's primary interface, and the upstream router it reaches.
peer_interface() {
  remote "ip route show default | awk '{print \$5}'"
}

upstream_gateway() {
  remote "ip route show default | awk '{print \$3}'"
}

upstream_gateway6() {
  remote "ip -6 route show default | awk '{print \$3}'"
}

# Install the capture that records what the far side observed.
#
# The sniffer prints "<source> <destination>" for every ICMP and ICMPv6 packet
# the interface received. The peer host's python3 is the only thing it needs.
install_observation_capture() {
  remote_root "cat > ${OBSERVED_SCRIPT}" <<'PYTHON'
import socket
import struct
import sys

interface = sys.argv[1]
reader = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
reader.bind((interface, 0))
while True:
    try:
        frame = reader.recv(65535)
    except OSError:
        break
    if len(frame) < 34:
        continue
    kind = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    if kind == 0x8100:
        kind = struct.unpack("!H", frame[16:18])[0]
        offset = 18
    if kind == 0x0800:
        if frame[offset + 9] != 1:
            continue
        source = socket.inet_ntop(socket.AF_INET, frame[offset + 12:offset + 16])
        destination = socket.inet_ntop(socket.AF_INET, frame[offset + 16:offset + 20])
    elif kind == 0x86DD:
        if frame[offset + 6] != 58:
            continue
        source = socket.inet_ntop(socket.AF_INET6, frame[offset + 8:offset + 24])
        destination = socket.inet_ntop(socket.AF_INET6, frame[offset + 24:offset + 40])
    else:
        continue
    print(source, destination, flush=True)
PYTHON
}

# Start the capture inside the LAN namespace.
#
# The capture is detached from the session and writes to a file, so it holds
# no channel open and its output never mixes with the driver's own. Its
# process id is recorded rather than matched by name: the capture's own path
# appears in the very command line that would start it, so a name match would
# find the starting shell as well.
start_observation_capture() {
  stop_observation_capture
  remote_root "rm -f ${OBSERVED_LOG}; \
          nohup ip netns exec ${LAN_NS} python3 -u ${OBSERVED_SCRIPT} ${LAN_IFACE} \
          > ${OBSERVED_LOG} 2>&1 < /dev/null & echo \$! > ${OBSERVED_PID}"
}

# Stop the capture, if it is running.
stop_observation_capture() {
  remote_root "if [ -f ${OBSERVED_PID} ]; then kill \$(cat ${OBSERVED_PID}) 2>/dev/null; fi; \
          rm -f ${OBSERVED_PID}"
}

# The source address the far side observed for the traffic towards an address.
#
# The capture's own log is read here rather than parsed on the peer host, so
# the filter stays a plain local expression and the far side's observation is
# reported exactly as it was recorded.
observed_source() {
  local address="${1:?the destination address is required}"
  local observed
  observed="$(remote_root "cat ${OBSERVED_LOG}" 2>/dev/null | \
    awk -v want="${address}" '$2 == want { source = $1 } END { print source }' || true)"
  if [ -z "${observed}" ]; then
    echo "the far side observed no traffic towards ${address}" >&2
    return 1
  fi
  printf '%s\n' "${observed}"
}

command="${1:?a peer subcommand is required}"
shift

case "${command}" in
  setup)
    # Builds the qualification topology on the peer host.
    #
    # The peer namespace and the LAN namespace are separate namespaces on one
    # machine, joined only by the root namespace. The forwarding rules make
    # the isolation explicit: the peer namespace cannot reach the LAN
    # namespace directly, so the only path to the downstream host is the
    # tunnel.
    physical="$(peer_interface)"
    gateway="${WGB_UPSTREAM_GATEWAY:-$(upstream_gateway)}"
    gateway6="${WGB_UPSTREAM_GATEWAY6:-$(upstream_gateway6)}"
    remote_root "sh -s" <<REMOTE
set -eu
physical='${physical}'
gateway='${gateway}'
gateway6='${gateway6}'
# A namespace that still has a process in it cannot be unmounted, and the
# delete spins on the busy mount. The processes are ended first, so the
# topology can be rebuilt without leaving a stuck teardown behind.
for ns in ${PEER_NS} ${LAN_NS}; do
  ip netns pids "\${ns}" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
  ip netns del "\${ns}" 2>/dev/null || true
done
ip link del vethp0 2>/dev/null || true
ip link del vethl0 2>/dev/null || true
ip netns add ${PEER_NS}
ip netns add ${LAN_NS}

# The peer namespace's own link.
ip link add vethp0 type veth peer name vethp1
ip link set vethp1 netns ${PEER_NS}
ip addr add ${PEER_LINK_ADDR}/24 dev vethp0
ip link set vethp0 up
ip -6 addr add ${PEER_LINK6}/64 dev vethp0 nodad
ip netns exec ${PEER_NS} ip addr add ${PEER_ADDR}/24 dev vethp1
ip netns exec ${PEER_NS} ip link set vethp1 up
ip netns exec ${PEER_NS} ip link set lo up
ip netns exec ${PEER_NS} ip -6 addr add ${PEER_ADDR6}/64 dev vethp1 nodad
ip netns exec ${PEER_NS} ip route add default via ${PEER_LINK_ADDR}
ip netns exec ${PEER_NS} ip -6 route add default via ${PEER_LINK6}

# The downstream LAN host's link.
ip link add vethl0 type veth peer name vethl1
ip link set vethl1 netns ${LAN_NS}
ip addr add ${LAN_GATEWAY_ADDR}/24 dev vethl0
ip link set vethl0 up
ip -6 addr add ${LAN_GATEWAY6}/64 dev vethl0 nodad
ip netns exec ${LAN_NS} ip addr add ${LAN_ADDR}/24 dev vethl1
ip netns exec ${LAN_NS} ip link set vethl1 up
ip netns exec ${LAN_NS} ip link set lo up
ip netns exec ${LAN_NS} ip -6 addr add ${LAN_ADDR6}/64 dev vethl1 nodad
ip netns exec ${LAN_NS} ip route add default via ${LAN_GATEWAY_ADDR}
ip netns exec ${LAN_NS} ip -6 route add default via ${LAN_GATEWAY6}

# The upstream router's route back to the tunnel pool. This is the return
# path the server side cannot observe for itself.
sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv6.conf.all.forwarding=1
ip route replace ${TUNNEL_PREFIX} via "\${gateway}" dev "\${physical}"
ip -6 route replace ${TUNNEL_PREFIX6} via "\${gateway6}" dev "\${physical}"

# The upstream router reaches the LAN host's addresses through this host, so
# the addresses are answered for on the host's own interface.
sysctl -q -w net.ipv6.conf."\${physical}".proxy_ndp=1
ip -6 neigh add proxy ${LAN_ADDR6} dev "\${physical}"
sysctl -q -w net.ipv4.conf."\${physical}".proxy_arp=1
ip neigh add proxy ${LAN_ADDR} dev "\${physical}"

# The peer namespace's traffic leaves as the peer host's own address, the way
# a peer behind NAT appears; the LAN host's traffic keeps its own address so
# the server's filter sees the pool source and the downstream source intact.
iptables -t nat -C POSTROUTING -s ${PEER_ADDR}/32 -o "\${physical}" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s ${PEER_ADDR}/32 -o "\${physical}" -j MASQUERADE

# Isolation: the peer namespace cannot reach the LAN namespace directly.
iptables -C FORWARD -i vethp0 -o vethl0 -j DROP 2>/dev/null || \
  iptables -A FORWARD -i vethp0 -o vethl0 -j DROP
iptables -C FORWARD -i vethl0 -o vethp0 -j DROP 2>/dev/null || \
  iptables -A FORWARD -i vethl0 -o vethp0 -j DROP
iptables -C FORWARD -i vethl0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i vethl0 -j ACCEPT
iptables -C FORWARD -o vethl0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -o vethl0 -j ACCEPT
iptables -C FORWARD -i vethp0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i vethp0 -j ACCEPT

echo 'the peer host topology is ready'
ip netns list
ip route show
ip -6 route show
REMOTE
    # The far side's own observation of the traffic that arrives at it.
    install_observation_capture
    start_observation_capture
    ;;
  peer-address)
    remote "ip -4 -o addr show scope global | awk '{print \$4}' | cut -d/ -f1 | head -1"
    ;;
  peer-gateway)
    upstream_gateway
    ;;
  peer-gateway6)
    upstream_gateway6
    ;;
  lan-address)
    echo "${LAN_ADDR}"
    ;;
  lan-address6)
    echo "${LAN_ADDR6}"
    ;;
  lan-route)
    remote_root "ip netns exec ${LAN_NS} ip route show; ip netns exec ${LAN_NS} ip -6 route show"
    ;;
  lan-host-ping)
    address="${1:?the address to ping is required}"
    remote_root "ip netns exec ${LAN_NS} ping -c 3 -W 2 ${address}" || true
    ;;
  lan-host-ping6)
    address="${1:?the address to ping is required}"
    remote_root "ip netns exec ${LAN_NS} ping -6 -c 3 -W 2 ${address}" || true
    ;;
  ping-lan)
    address="${1:?the downstream address to ping is required}"
    remote_root "ip netns exec ${PEER_NS} ping -c 3 -W 2 ${address}" || true
    ;;
  ping-lan6)
    address="${1:?the downstream address to ping is required}"
    remote_root "ip netns exec ${PEER_NS} ping -6 -c 3 -W 2 ${address}" || true
    ;;
  spoof)
    address="${1:?the downstream address to spoof towards is required}"
    # A packet that claims to come from outside the tunnel pool. The address
    # is bound on the peer namespace's loopback so it can be sourced, and it
    # is not in the peer's allowed sources, so the tunnel itself must refuse
    # it before it can reach the server.
    remote_root "ip netns exec ${PEER_NS} ip addr add 10.99.0.9/32 dev lo 2>/dev/null || true; \
            ip netns exec ${PEER_NS} ping -c 3 -W 2 -I 10.99.0.9 ${address}" || true
    ;;
  apply)
    config="${1:?the exported client configuration path is required}"
    server_v4="${2:?the server IPv4 tunnel address is required}"
    server_v6="${3:-}"
    attempt_v4="${4:?the attempted downstream IPv4 prefix is required}"
    attempt_v6="${5:-}"
    rewritten="$(mktemp)"
    trap 'rm -f "${rewritten}"' EXIT
    # The exported configuration carries the client's route policy as
    # AllowedIPs, which on a real peer would blackhole the peer's own
    # traffic. The peer keeps its own routes and sends only the tunnel's
    # addresses and the attempted downstream ranges into the tunnel. The
    # attempted ranges are wider than the prefixes the server approved, on
    # purpose: the server's own filter has to be what rejects a destination
    # outside the approved prefix.
    awk -v v4="${server_v4}" -v v6="${server_v6}" -v a4="${attempt_v4}" -v a6="${attempt_v6}" '
      /^[[:space:]]*DNS[[:space:]]*=/ { next }
      /^[[:space:]]*AllowedIPs[[:space:]]*=/ {
        list = v4
        if (v6 != "") { list = list ", " v6 }
        list = list ", " a4
        if (a6 != "") { list = list ", " a6 }
        print "AllowedIPs = " list
        next
      }
      { print }
    ' "${config}" > "${rewritten}"
    "${SCP[@]}" "${rewritten}" "${TARGET}:/tmp/${PEER_IFACE}.conf"
    remote_root "install -d -m 700 /etc/wireguard && \
            install -m 600 /tmp/${PEER_IFACE}.conf ${REMOTE_CONFIG} && \
            (ip netns exec ${PEER_NS} wg-quick down ${PEER_IFACE} 2>/dev/null || true) && \
            ip netns exec ${PEER_NS} wg-quick up ${PEER_IFACE}"
    ;;
  status)
    remote_root "ip netns exec ${PEER_NS} wg show ${PEER_IFACE}"
    ;;
  handshake)
    remote_root "ip netns exec ${PEER_NS} wg show ${PEER_IFACE} latest-handshakes | awk '{print \$2}' | head -1"
    ;;
  observed-source|observed-source6)
    observed_source "${1:?the destination address is required}"
    ;;
  teardown)
    stop_observation_capture
    remote_root "ip netns exec ${PEER_NS} wg-quick down ${PEER_IFACE} 2>/dev/null || true; \
            rm -f ${REMOTE_CONFIG} /tmp/${PEER_IFACE}.conf"
    ;;
  *)
    echo "unknown peer subcommand: ${command}" >&2
    exit 2
    ;;
esac
