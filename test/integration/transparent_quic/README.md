# Transparent QUIC / HTTP-3 interception — manual integration test

Transparent QUIC interception uses Linux **TPROXY**, which requires root/`CAP_NET_ADMIN` and a
real forwarding path, so it cannot run in the normal pytest CI. The automated coverage lives in
`test/mitmproxy/proxy/test_udp_transparent.py` and
`test/mitmproxy/proxy/test_mode_servers.py::test_transparent_udp` (both run unprivileged, since
`IP_RECVORIGDSTADDR` does not need `CAP_NET_ADMIN`). This directory adds a reproducible end-to-end
check against a live server.

`netns_tproxy.sh` builds the gateway topology on a single machine using a network namespace as the
client (TPROXY only sees *forwarded* traffic, so the client must be behind the host):

```
[ netns client ] --UDP/443--> [ host: TPROXY -> mitmproxy ] --QUIC--> [ real server ]
```

## Steps

```bash
# 1. Trust mitmproxy's CA once (start mitmproxy, or copy ~/.mitmproxy/mitmproxy-ca-cert.pem).

# 2. Set up the namespace + TPROXY rules.
sudo ./netns_tproxy.sh up

# 3. In another terminal, run THIS FORK's mitmdump as root (so it can open IP_TRANSPARENT
#    sockets). Two caveats: a system-installed `mitmdump` will not have this feature, and
#    mitmproxy pins aioquic==1.2.0 (newer aioquic breaks its HTTP/3 layer). Run it from a
#    venv that provides the pinned aioquic. From the repository root:
#
#      python -m venv --system-site-packages .venv
#      .venv/bin/pip install "aioquic==1.2.0"
#
#    Then launch, pointing at the CA the client trusts:
sudo env "PYTHONPATH=$PWD" "$PWD/.venv/bin/python" \
    -c "from mitmproxy.tools.main import mitmdump; mitmdump()" \
    --mode transparent@8080 --showhost --set confdir="$HOME/.mitmproxy"

# 4. Make a real HTTP/3 request from the namespace, through the proxy, to the internet.
sudo ./netns_tproxy.sh test        # curl --http3-only https://quic.anzepintar.com/

# 5. (optional) Prove the reply path spoofs the server's source address.
sudo ./netns_tproxy.sh capture     # tcpdump udp/443 on the veth

# 6. Tear everything down.
sudo ./netns_tproxy.sh down
```

`curl` must be built with HTTP/3 support for step 4; `--http3-only` forces QUIC so the test cannot
silently fall back to TCP. Override the target with `TEST_URL=...` and the CA with `MITMPROXY_CA=...`.

## Pass criteria (no faked results)

1. **Content is visible.** The request in step 4 succeeds *through* the proxy and the decrypted
   HTTP/3 request and response (headers + body) appear in mitmproxy's flow list. This is the primary
   goal: full visibility with only the client's trust (the installed CA) and no server access.
2. **Client leg uses the forged cert.** The certificate the client accepts chains to the mitmproxy
   CA.
3. **Server leg is genuine.** mitmproxy opens its own QUIC connection to the real server and
   validates the server's certificate against the public root store (default, i.e. not
   `--ssl-insecure`) — confirming no server cooperation is needed.
4. **Reply-path spoofing works.** In the `capture` output, datagrams from mitmproxy back to the
   client have the **original server address** as their source (not the proxy's), which is what lets
   the client's QUIC stack accept them.
5. **Generality.** Repeat step 4 with a second, unrelated public HTTP/3 site to confirm the design
   is not specific to the test server. Comparing with `mitmdump --mode reverse:quic://<host>` should
   show the same decrypted content.

A rejected forged certificate (e.g. a pinning client) shows up as a QUIC handshake that stalls and
retransmits rather than a clean error — expected, and a property of the client, not the proxy.
