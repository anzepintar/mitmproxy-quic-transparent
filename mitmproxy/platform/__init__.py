import re
import socket
import sys
from collections.abc import Callable


def init_transparent_mode() -> None:
    """
    Initialize transparent mode.
    """


original_addr: Callable[[socket.socket], tuple[str, int]] | None
"""
Get the original destination for the given socket.
This function will be None if transparent mode is not supported.
"""

transparent_udp_supported: bool = False
"""
Whether transparent mode can also intercept UDP-based protocols (QUIC/HTTP3).
This currently requires Linux with TPROXY; on other platforms transparent mode is TCP-only.
"""

if re.match(r"linux(?:2)?", sys.platform):
    from . import linux

    original_addr = linux.original_addr
    transparent_udp_supported = True
elif sys.platform == "darwin" or sys.platform.startswith("freebsd"):
    from . import osx

    original_addr = osx.original_addr
elif sys.platform.startswith("openbsd"):
    from . import openbsd

    original_addr = openbsd.original_addr
elif sys.platform == "win32":
    from . import windows

    resolver = windows.Resolver()
    init_transparent_mode = resolver.setup  # noqa
    original_addr = resolver.original_addr
else:
    original_addr = None

__all__ = ["original_addr", "init_transparent_mode", "transparent_udp_supported"]
