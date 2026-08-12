import asyncio
import socket
import struct

import pytest

from ...conftest import skip_not_linux
from mitmproxy.platform import linux
from mitmproxy.proxy import udp_transparent


def loopback_listener(host: str, port: int) -> socket.socket:
    """
    Like `linux.create_tproxy_listener`, but without IP_TRANSPARENT so that tests can run
    unprivileged. IP_RECVORIGDSTADDR does not require CAP_NET_ADMIN, so datagrams sent
    directly to the (loopback) listener still carry their original destination.
    """
    if ":" in host:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(linux.SOL_IPV6, linux.IPV6_RECVORIGDSTADDR, 1)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_IP, linux.IP_RECVORIGDSTADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)
    sock.bind((host, port))
    return sock


def loopback_reply_socket(original_dst: tuple[str, int]) -> socket.socket:
    """Unprivileged stand-in for `linux.create_reply_socket` (no source spoofing)."""
    family = socket.AF_INET6 if ":" in original_dst[0] else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    return sock


def test_parse_origdst_ipv4():
    sa_in = (
        struct.pack("=H", socket.AF_INET)
        + struct.pack("!H", 443)
        + socket.inet_aton("1.2.3.4")
        + b"\x00" * 8
    )
    ancdata = [(socket.SOL_IP, linux.IP_ORIGDSTADDR, sa_in)]
    assert linux.parse_origdst(ancdata) == ("1.2.3.4", 443)


def test_parse_origdst_ipv6():
    sa_in6 = (
        struct.pack("=H", socket.AF_INET6)
        + struct.pack("!H", 8443)
        + b"\x00" * 4
        + socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        + b"\x00" * 4
    )
    ancdata = [(linux.SOL_IPV6, linux.IPV6_ORIGDSTADDR, sa_in6)]
    assert linux.parse_origdst(ancdata) == ("2001:db8::1", 8443)


def test_parse_origdst_missing():
    with pytest.raises(RuntimeError):
        linux.parse_origdst([])


async def test_datagram_stream_roundtrip():
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.setblocking(False)
    reply = loopback_reply_socket(("9.9.9.9", 443))
    removed = []

    class FakeServer:
        def _remove_flow(self, c, d):
            removed.append((c, d))

    stream = udp_transparent.DatagramStream(
        FakeServer(), client.getsockname(), ("9.9.9.9", 443), reply
    )

    assert stream.get_extra_info("transport_protocol") == "udp"
    assert stream.get_extra_info("peername") == client.getsockname()
    assert stream.get_extra_info("sockname") == ("9.9.9.9", 443)
    assert stream.get_extra_info("original_dst") == ("9.9.9.9", 443)
    assert stream.get_extra_info("unknown", "default") == "default"

    # one datagram per read()
    stream.feed(b"first")
    stream.feed(b"second")
    assert await stream.read(65535) == b"first"
    assert await stream.read(65535) == b"second"

    # write() reaches the client
    stream.write(b"reply")
    loop = asyncio.get_running_loop()
    data = await loop.sock_recv(client, 65535)
    assert data == b"reply"

    # close() unblocks read() with EOF and unregisters the flow
    stream.close()
    assert stream.is_closing()
    assert removed == [(client.getsockname(), ("9.9.9.9", 443))]
    assert await stream.read(65535) == b""

    client.close()


async def test_datagram_stream_idle_timeout(monkeypatch):
    monkeypatch.setattr(udp_transparent, "FLOW_IDLE_TIMEOUT", 0.01)
    reply = loopback_reply_socket(("9.9.9.9", 443))
    removed = []

    class FakeServer:
        def _remove_flow(self, c, d):
            removed.append((c, d))

    stream = udp_transparent.DatagramStream(
        FakeServer(), ("127.0.0.1", 5000), ("9.9.9.9", 443), reply
    )
    await asyncio.sleep(0.05)
    assert stream.is_closing()
    assert removed  # flow was garbage-collected after inactivity


@skip_not_linux
async def test_transparent_udp_server(monkeypatch):
    monkeypatch.setattr(linux, "create_reply_socket", loopback_reply_socket)

    handled: list[udp_transparent.DatagramStream] = []

    async def handle_stream(reader, writer):
        # reader and writer are the same DatagramStream (as for the Rust UDP server).
        assert reader is writer
        handled.append(reader)
        data = await reader.read(65535)
        reader.write(data.upper())

    listener = loopback_listener("127.0.0.1", 0)
    server = udp_transparent.TransparentUdpServer(listener, handle_stream)
    server_addr = server.getsockname()

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.setblocking(False)
    loop = asyncio.get_running_loop()

    # First datagram creates a flow; the recovered original destination is the address the
    # client actually sent to (no NAT on loopback).
    client.sendto(b"hello", server_addr)
    reply = await asyncio.wait_for(loop.sock_recv(client, 65535), 2)
    assert reply == b"HELLO"
    assert len(handled) == 1
    assert handled[0].get_extra_info("original_dst") == server_addr
    assert handled[0].get_extra_info("peername") == client.getsockname()

    # A datagram from a second client is demultiplexed into a separate flow.
    client2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client2.bind(("127.0.0.1", 0))
    client2.setblocking(False)
    client2.sendto(b"world", server_addr)
    reply2 = await asyncio.wait_for(loop.sock_recv(client2, 65535), 2)
    assert reply2 == b"WORLD"
    assert len(handled) == 2

    server.close()
    client.close()
    client2.close()
