"""
Transparent UDP interception for QUIC/HTTP3 on Linux.

mitmproxy's transparent mode redirects TCP connections into the proxy and recovers the
original destination via `SO_ORIGINAL_DST` (see `mitmproxy.platform`). UDP-based protocols
such as QUIC cannot use that mechanism, so on Linux we intercept them with TPROXY instead:
an `iptables`/`nftables` rule diverts the datagrams to an `IP_TRANSPARENT` socket, which
also learns each datagram's original destination from `IP_RECVORIGDSTADDR` ancillary data.

This module turns that raw socket into per-flow objects that quack like a
`mitmproxy_rs.Stream`, so that the rest of the proxy (connection handling, the QUIC layers,
certificate generation, ...) works exactly as it does for the Rust-based UDP servers.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import Callable
from collections.abc import Coroutine
from typing import Any

from mitmproxy.connection import Address
from mitmproxy.platform import linux
from mitmproxy.utils import asyncio_utils

logger = logging.getLogger(__name__)

# A flow is closed after this many seconds without any datagram from the client. UDP has
# no connection teardown, so this prevents leaking per-flow state and sockets.
FLOW_IDLE_TIMEOUT = 60

# Flows are demultiplexed by the (client, original destination) address pair.
FlowKey = tuple[Address, Address]

# The `handle_stream` callback provided by the server instance. It is invoked with the
# per-flow stream as both reader and writer, mirroring the Rust UDP server callback.
HandleStream = Callable[..., Coroutine[Any, Any, None]]


class DatagramStream:
    """
    A single transparent UDP flow. It duck-types the parts of `mitmproxy_rs.Stream` that
    `mitmproxy.proxy.server` relies on, so that no downstream code needs to special-case it.
    """

    def __init__(
        self,
        server: TransparentUdpServer,
        client: Address,
        original_dst: Address,
        reply_sock: socket.socket,
    ) -> None:
        self._server = server
        self._client = client
        self._original_dst = original_dst
        self._reply_sock = reply_sock
        self._incoming: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._closed = False
        self._idle_handle: asyncio.TimerHandle | None = None
        self._reset_idle_timer()

    # inbound: client -> proxy

    def feed(self, data: bytes) -> None:
        if self._closed:
            return
        self._reset_idle_timer()
        self._incoming.put_nowait(data)

    async def read(self, n: int) -> bytes:
        # `n` is ignored: like the Rust UDP stream we return exactly one datagram per call
        # so that QUIC datagram boundaries are preserved. An empty result signals EOF.
        data = await self._incoming.get()
        if data is None:
            return b""
        return data

    # outbound: proxy -> client

    def write(self, data: bytes) -> None:
        if self._closed:
            return
        try:
            self._reply_sock.sendto(data, self._client)
        except OSError as e:  # pragma: no cover - best effort, QUIC retransmits
            logger.debug(
                f"Failed to send transparent UDP reply to {self._client}: {e!r}"
            )

    async def drain(self) -> None:
        pass

    def write_eof(self) -> None:
        # UDP is message-based and has no half-close.
        pass

    # lifecycle

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._idle_handle is not None:
            self._idle_handle.cancel()
            self._idle_handle = None
        self._incoming.put_nowait(None)  # unblock a pending read() with EOF
        self._reply_sock.close()
        self._server._remove_flow(self._client, self._original_dst)

    def is_closing(self) -> bool:
        return self._closed

    async def wait_closed(self) -> None:
        pass

    def _reset_idle_timer(self) -> None:
        loop = asyncio.get_running_loop()
        if self._idle_handle is not None:
            self._idle_handle.cancel()
        self._idle_handle = loop.call_later(FLOW_IDLE_TIMEOUT, self.close)

    def get_extra_info(self, name: str, default=None):
        return {
            "transport_protocol": "udp",
            "peername": self._client,
            "sockname": self._original_dst,
            "original_dst": self._original_dst,
        }.get(name, default)

    def __repr__(self) -> str:  # pragma: no cover
        return f"DatagramStream({self._client} -> {self._original_dst})"


class TransparentUdpServer:
    """
    A transparent UDP listener that receives TPROXY-diverted datagrams, demultiplexes them
    into per-flow `DatagramStream`s, and starts `handle_stream` for each new flow. It
    duck-types `mitmproxy_rs.udp.UdpServer` (`getsockname`/`close`/`wait_closed`).
    """

    def __init__(self, sock: socket.socket, handle_stream: HandleStream) -> None:
        self._sock = sock
        self._handle_stream = handle_stream
        self._flows: dict[FlowKey, DatagramStream] = {}
        self._tasks: set[asyncio.Task] = set()
        self._loop = asyncio.get_running_loop()
        self._loop.add_reader(self._sock.fileno(), self._on_readable)

    def getsockname(self) -> Address:
        return self._sock.getsockname()

    def _on_readable(self) -> None:
        # Drain every datagram currently queued on the socket.
        while True:
            try:
                data, ancdata, _flags, client = self._sock.recvmsg(
                    65535, socket.CMSG_SPACE(28)
                )
            except BlockingIOError:
                return
            except OSError as e:  # pragma: no cover
                logger.debug(f"Transparent UDP socket error: {e!r}")
                return
            try:
                original_dst = linux.parse_origdst(ancdata)
            except Exception as e:  # pragma: no cover
                logger.debug(f"Dropping transparent UDP datagram: {e!r}")
                continue
            self._dispatch(client, original_dst, data)

    def _dispatch(self, client: Address, original_dst: Address, data: bytes) -> None:
        key = (client, original_dst)
        stream = self._flows.get(key)
        if stream is None:
            try:
                reply_sock = linux.create_reply_socket(original_dst)
            except OSError as e:  # pragma: no cover
                logger.debug(
                    f"Failed to open reply socket for {original_dst}: {e!r}, dropping flow."
                )
                return
            stream = DatagramStream(self, client, original_dst, reply_sock)
            self._flows[key] = stream
            task = asyncio_utils.create_task(
                self._handle_stream(stream, stream),
                name=f"transparent udp {client} -> {original_dst}",
                keep_ref=False,
                client=client,
            )
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        stream.feed(data)

    def _remove_flow(self, client: Address, original_dst: Address) -> None:
        self._flows.pop((client, original_dst), None)

    def close(self) -> None:
        try:
            self._loop.remove_reader(self._sock.fileno())
        except (OSError, ValueError):  # pragma: no cover
            pass
        self._sock.close()
        for stream in list(self._flows.values()):
            stream.close()
        for task in self._tasks:
            task.cancel()

    async def wait_closed(self) -> None:
        pass

    def __repr__(self) -> str:  # pragma: no cover
        return f"TransparentUdpServer({self.getsockname()})"


def start(
    host: str, port: int, handle_stream: HandleStream
) -> list[TransparentUdpServer]:
    """
    Start transparent UDP listener(s) for QUIC/HTTP3 interception.

    Mirrors the dual-stack behavior of `AsyncioServerInstance.listen`: for a wildcard host
    we bind separate IPv4 and IPv6 sockets so that both share the same port.
    """
    servers = []
    if host == "":
        servers.append(_start_one("0.0.0.0", port, handle_stream))
        try:
            servers.append(_start_one("::", port, handle_stream))
        except OSError:  # pragma: no cover
            logger.debug("Failed to listen on '::' for transparent UDP, IPv4 only.")
    else:
        servers.append(_start_one(host, port, handle_stream))
    return servers


def _start_one(
    host: str, port: int, handle_stream: HandleStream
) -> TransparentUdpServer:
    sock = linux.create_tproxy_listener(host, port)
    return TransparentUdpServer(sock, handle_stream)
