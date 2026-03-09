from __future__ import annotations

import socket
import ssl
from abc import ABC, abstractmethod
from typing import Dict

from ws_tunnel import establish_ws_tunnel


class TunnelStrategy(ABC):
    """
    Abstract Strategy that returns a connected *raw* socket ready for Paramiko.
    """

    def __init__(self, cfg: Dict):
        # Configuration is injected, avoiding global state.
        self.cfg = cfg

    @abstractmethod
    def establish(self) -> socket.socket:   # pragma: no cover
        """
        Establish the tunnel and return an already-connected socket.
        Must raise an exception on failure.
        """
        raise NotImplementedError


# --------------------------------------------------------------------------- #
#                             Concrete strategies                             #
# --------------------------------------------------------------------------- #

class DirectStrategy(TunnelStrategy):
    """
    Straight TCP connection to TARGET_HOST:TARGET_PORT.
    """

    def establish(self) -> socket.socket:
        return socket.create_connection(
            (self.cfg["TARGET_HOST"], self.cfg["TARGET_PORT"])
        )


class HttpPayloadStrategy(TunnelStrategy):
    """
    Default (legacy) mode: plain-text connection to PROXY_HOST where we run the
    custom HTTP/WebSocket upgrade payload defined in CONFIG['PAYLOAD_TEMPLATE'].
    """

    def establish(self) -> socket.socket:
        return establish_ws_tunnel(
            proxy_host=self.cfg["PROXY_HOST"],
            proxy_port=self.cfg["PROXY_PORT"],
            target_host=self.cfg["TARGET_HOST"],
            target_port=self.cfg["TARGET_PORT"],
            payload_template=self.cfg["payload_template"],
            use_tls=False,
        )


class SNIFrontedStrategy(TunnelStrategy):
    """
    Like HttpPayloadStrategy but wrapped in TLS with an arbitrary SNI (domain
    fronting).  The TLS layer hides the HTTP upgrade and the front domain can
    be an unrelated host served by the same CDN.
    """

    def establish(self) -> socket.socket:
        # 1. Build a TLS socket to PROXY_HOST with forged SNI.
        raw_sock = socket.create_connection(
            (self.cfg["PROXY_HOST"], self.cfg["PROXY_PORT"])
        )
        ctx = ssl.create_default_context()
        tls_sock = ctx.wrap_socket(
            raw_sock,
            server_hostname=(
                self.cfg.get("front_domain") or self.cfg["PROXY_HOST"]
            ),
        )

        # 2. Perform the exact same WebSocket upgrade inside that TLS tunnel.
        return establish_ws_tunnel(
            proxy_host=self.cfg["PROXY_HOST"],
            proxy_port=self.cfg["PROXY_PORT"],
            target_host=self.cfg["TARGET_HOST"],
            target_port=self.cfg["TARGET_PORT"],
            payload_template=self.cfg["payload_template"],
            sock=tls_sock,         # Re-use the already-encrypted socket
            use_tls=False,         # Don’t double-wrap
        )


# --------------------------------------------------------------------------- #
#                                Factory helper                               #
# --------------------------------------------------------------------------- #

def get_strategy(mode: str) -> type[TunnelStrategy]:
    """
    Map CONFIG['MODE'] to its Strategy class.

    >>> strategy_cls = get_strategy("sni_fronted")
    >>> tunnel = strategy_cls(cfg).establish()
    """
    table = {
        "direct":       DirectStrategy,
        "http_payload": HttpPayloadStrategy,
        "sni_fronted":  SNIFrontedStrategy,
    }
    try:
        return table[mode.lower()]
    except KeyError:
        valid = ", ".join(table.keys())
        raise ValueError(f"Unknown MODE '{mode}'. Valid choices: {valid}")
