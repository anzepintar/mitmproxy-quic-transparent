import socket
import struct

# Python's socket module does not have these constants
SO_ORIGINAL_DST = 80
SOL_IPV6 = 41

# Constants for transparent UDP (QUIC/HTTP3) interception via TPROXY.
# These are not (reliably) exposed by Python's socket module across all supported
# versions, so we define the Linux values explicitly (see linux/in.h and in6.h).
IP_TRANSPARENT = 19
IP_RECVORIGDSTADDR = 20
IP_ORIGDSTADDR = 20
IPV6_TRANSPARENT = 75
IPV6_RECVORIGDSTADDR = 74
IPV6_ORIGDSTADDR = 74


def original_addr(csock: socket.socket) -> tuple[str, int]:
    # Get the original destination on Linux.
    # In theory, this can be done using the following syscalls:
    #     sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    #     sock.getsockopt(SOL_IPV6, SO_ORIGINAL_DST, 28)
    #
    # In practice, it is a bit more complex:
    #  1. We cannot rely on sock.family to decide which syscall to use because of IPv4-mapped
    #     IPv6 addresses. If sock.family is AF_INET6 while sock.getsockname() is ::ffff:127.0.0.1,
    #     we need to call the IPv4 version to get a result.
    #  2. We can't just try the IPv4 syscall and then do IPv6 if that doesn't work,
    #     because doing the wrong syscall can apparently crash the whole Python runtime.
    # As such, we use a heuristic to check which syscall to do.
    is_ipv4 = "." in csock.getsockname()[0]  # either 127.0.0.1 or ::ffff:127.0.0.1
    if is_ipv4:
        # the struct returned here should only have 8 bytes, but invoking sock.getsockopt
        # with buflen=8 doesn't work.
        dst = csock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port, raw_ip = struct.unpack_from("!2xH4s", dst)
        ip = socket.inet_ntop(socket.AF_INET, raw_ip)
    else:
        dst = csock.getsockopt(SOL_IPV6, SO_ORIGINAL_DST, 28)
        port, raw_ip = struct.unpack_from("!2xH4x16s", dst)
        ip = socket.inet_ntop(socket.AF_INET6, raw_ip)
    return ip, port


def create_tproxy_listener(host: str, port: int) -> socket.socket:
    """
    Create a non-blocking UDP socket bound to *host:port* that receives datagrams
    redirected by an iptables/nftables TPROXY rule.

    IP_TRANSPARENT lets the socket accept datagrams that were originally destined for a
    foreign address (i.e. the real server), and IP_RECVORIGDSTADDR makes the kernel
    attach each datagram's original destination as ancillary data (see `parse_origdst`).
    """
    if ":" in host:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(SOL_IPV6, IPV6_TRANSPARENT, 1)
        sock.setsockopt(SOL_IPV6, IPV6_RECVORIGDSTADDR, 1)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        sock.setsockopt(socket.SOL_IP, IP_RECVORIGDSTADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)
    sock.bind((host, port))
    return sock


def parse_origdst(ancdata: list[tuple[int, int, bytes]]) -> tuple[str, int]:
    """
    Extract the original destination address from the ancillary data returned by
    `socket.recvmsg` on a socket created with `create_tproxy_listener`.
    """
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == socket.SOL_IP and cmsg_type == IP_ORIGDSTADDR:
            port, raw_ip = struct.unpack_from("!2xH4s", cmsg_data)
            return socket.inet_ntop(socket.AF_INET, raw_ip), port
        if cmsg_level == SOL_IPV6 and cmsg_type == IPV6_ORIGDSTADDR:
            port, raw_ip = struct.unpack_from("!2xH4x16s", cmsg_data)
            return socket.inet_ntop(socket.AF_INET6, raw_ip), port
    raise RuntimeError("received a datagram without original destination information")


def create_reply_socket(original_dst: tuple[str, int]) -> socket.socket:
    """
    Create a non-blocking UDP socket that sends datagrams *from* `original_dst`, spoofing
    the source address so that replies appear to come from the real server. This is the
    reply counterpart to `create_tproxy_listener` and also requires IP_TRANSPARENT.
    """
    if ":" in original_dst[0]:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(SOL_IPV6, IPV6_TRANSPARENT, 1)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
    # Several concurrent flows may target the same server address, so allow the reuse of
    # the (foreign) source address across per-flow reply sockets.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setblocking(False)
    sock.bind(original_dst)
    return sock
