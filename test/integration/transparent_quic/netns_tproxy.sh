#!/usr/bin/env bash
#
# Reproducible transparent QUIC/HTTP-3 interception harness.
#
# TPROXY operates on *forwarded* traffic in the mangle PREROUTING chain, so this script
# uses a network namespace as the "client": its traffic is routed through the host, where
# the TPROXY rule diverts UDP/443 into mitmproxy. This mirrors the real gateway topology
# (client -> mitmproxy box -> internet) on a single machine, without a second device.
#
# Usage (run as root):
#   sudo ./netns_tproxy.sh up            # create namespace + TPROXY rules
#   mitmdump --mode transparent@8080 --showhost      # in another terminal (as root)
#   sudo ./netns_tproxy.sh test          # make an HTTP/3 request through the proxy
#   sudo ./netns_tproxy.sh capture       # optional: tcpdump the diverted traffic
#   sudo ./netns_tproxy.sh down          # tear everything down
#
# The client only needs mitmproxy's CA. We pass it to curl via --cacert; set MITMPROXY_CA
# to override its location.
set -euo pipefail

NS=mitmns
VETH_HOST=veth-host
VETH_NS=veth-ns
SUBNET=10.77.0
HOST_IP=${SUBNET}.1
NS_IP=${SUBNET}.2
PROXY_PORT=${PROXY_PORT:-8080}
MARK=1
TABLE=100
TEST_URL=${TEST_URL:-https://quic.anzepintar.com/}
UPLINK=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") print $(i+1); exit}')

_user_home() { eval echo "~${SUDO_USER:-$USER}"; }
CA=${MITMPROXY_CA:-$(_user_home)/.mitmproxy/mitmproxy-ca-cert.pem}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root (e.g. with sudo)." >&2
        exit 1
    fi
}

up() {
    require_root
    echo "[*] Uplink interface: ${UPLINK:-<none detected>}"
    sysctl -q -w net.ipv4.ip_forward=1

    ip netns add "$NS"
    ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
    ip link set "$VETH_NS" netns "$NS"

    ip addr add "${HOST_IP}/24" dev "$VETH_HOST"
    ip link set "$VETH_HOST" up

    ip netns exec "$NS" ip addr add "${NS_IP}/24" dev "$VETH_NS"
    ip netns exec "$NS" ip link set "$VETH_NS" up
    ip netns exec "$NS" ip link set lo up
    ip netns exec "$NS" ip route add default via "$HOST_IP"

    # Give the namespace a resolver and let its non-diverted traffic reach the internet.
    mkdir -p "/etc/netns/$NS"
    echo "nameserver 1.1.1.1" > "/etc/netns/$NS/resolv.conf"
    if [[ -n "$UPLINK" ]]; then
        iptables -t nat -A POSTROUTING -s "${SUBNET}.0/24" -o "$UPLINK" -j MASQUERADE
    fi

    # TPROXY: divert QUIC (UDP/443) coming from the namespace to mitmproxy on PROXY_PORT.
    ip rule add fwmark "$MARK" lookup "$TABLE"
    ip route add local 0.0.0.0/0 dev lo table "$TABLE"
    iptables -t mangle -A PREROUTING -i "$VETH_HOST" -p udp --dport 443 \
        -j TPROXY --on-port "$PROXY_PORT" --tproxy-mark "$MARK"

    echo "[+] Namespace '$NS' ready. Now start mitmproxy as root, e.g.:"
    echo "      mitmdump --mode transparent@${PROXY_PORT} --showhost"
}

test_run() {
    require_root
    if [[ ! -f "$CA" ]]; then
        echo "mitmproxy CA not found at $CA (start mitmproxy once, or set MITMPROXY_CA)." >&2
        exit 1
    fi
    echo "[*] Requesting $TEST_URL over HTTP/3 through the transparent proxy..."
    ip netns exec "$NS" curl --http3-only --cacert "$CA" -sS -o /dev/null -w \
        'HTTP %{http_version} status %{http_code} via %{remote_ip}:%{remote_port}\n' \
        "$TEST_URL"
    echo "[+] Success means: the request completed over HTTP/3, the forged certificate was"
    echo "    accepted (chains to the mitmproxy CA), and the flow is visible in mitmproxy."
}

capture() {
    require_root
    echo "[*] Capturing UDP/443 on $VETH_HOST (Ctrl-C to stop). Replies should have the"
    echo "    original server address as their source, proving reply-path spoofing works."
    tcpdump -ni "$VETH_HOST" 'udp port 443'
}

down() {
    require_root
    iptables -t mangle -D PREROUTING -i "$VETH_HOST" -p udp --dport 443 \
        -j TPROXY --on-port "$PROXY_PORT" --tproxy-mark "$MARK" 2>/dev/null || true
    ip route del local 0.0.0.0/0 dev lo table "$TABLE" 2>/dev/null || true
    ip rule del fwmark "$MARK" lookup "$TABLE" 2>/dev/null || true
    if [[ -n "$UPLINK" ]]; then
        iptables -t nat -D POSTROUTING -s "${SUBNET}.0/24" -o "$UPLINK" -j MASQUERADE 2>/dev/null || true
    fi
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$VETH_HOST" 2>/dev/null || true
    rm -rf "/etc/netns/$NS"
    echo "[+] Torn down."
}

case "${1:-}" in
    up) up ;;
    test) test_run ;;
    capture) capture ;;
    down) down ;;
    *) echo "usage: $0 {up|test|capture|down}" >&2; exit 2 ;;
esac
