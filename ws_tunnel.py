from __future__ import annotations

import socket
import ssl
from typing import Optional


# --------------------------------------------------------------------------- #
#                               Helper utilities                              #
# --------------------------------------------------------------------------- #
def replace_placeholders(payload: str, target_host: str, target_port: int) -> bytes:
    """
    Swap placeholders inside *payload*:
      [host]  → "target_host:target_port"
      [crlf]  → "\r\n"

    Note: [split] is intentionally left as-is here so the caller can
    split on it after this substitution.
    """
    host_value = f"{target_host}:{target_port}"
    payload = payload.replace("[host]", host_value).replace("[crlf]", "\r\n")
    return payload.encode()


def read_headers(sock: socket.socket) -> bytes:
    """
    Read HTTP response headers byte-by-byte until \r\n\r\n.

    Stops *exactly* at the end of the header block so that no payload
    bytes are consumed from the socket buffer.
    """
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data


def drain_response_body(sock: socket.socket, headers: bytes) -> None:
    """
    Consume the response body so the socket is positioned at the start
    of the next HTTP message.

    Handles:
      - Transfer-Encoding: chunked
      - Content-Length: N
      - No body (1xx, 204, 304)
    """
    headers_lower = headers.lower()

    first_line = headers.split(b"\r\n", 1)[0]
    try:
        status_code = int(first_line.split(b" ", 2)[1])
    except (IndexError, ValueError):
        status_code = 0

    if status_code in (204, 304) or 100 <= status_code < 200:
        return

    if b"transfer-encoding: chunked" in headers_lower:
        _drain_chunked(sock)
    else:
        cl = _extract_content_length(headers_lower)
        if cl is not None and cl > 0:
            _recv_exactly(sock, cl)


def _drain_chunked(sock: socket.socket) -> None:
    """Read and discard a chunked-encoded body."""
    while True:
        size_line = b""
        while not size_line.endswith(b"\r\n"):
            byte = sock.recv(1)
            if not byte:
                return
            size_line += byte

        chunk_size = int(size_line.strip().split(b";")[0], 16)
        if chunk_size == 0:
            sock.recv(2)  # trailing CRLF
            return

        _recv_exactly(sock, chunk_size + 2)  # data + CRLF


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from *sock*."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _extract_content_length(headers_lower: bytes) -> Optional[int]:
    for line in headers_lower.split(b"\r\n"):
        if line.startswith(b"content-length:"):
            try:
                return int(line.split(b":", 1)[1].strip())
            except ValueError:
                pass
    return None


def _is_upgrade_response(headers: bytes) -> bool:
    """
    Return True if the response signals that the tunnel is now live:
      - 101 Switching Protocols  (standard WebSocket)
      - 200 OK + Connection: Upgrade  (some non-standard proxies)
    """
    first_line = headers.split(b"\r\n", 1)[0]
    if b" 101 " in first_line:
        return True
    if b" 200 " in first_line and b"upgrade" in headers.lower():
        return True
    return False


# --------------------------------------------------------------------------- #
#                              Public entry point                              #
# --------------------------------------------------------------------------- #
def establish_ws_tunnel(
    *,
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    payload_template: str,
    use_tls: bool = False,
    sock: Optional[socket.socket] = None,
) -> socket.socket:
    """
    Perform the WebSocket/HTTP upgrade handshake and return a socket ready
    for Paramiko (SSH).

    Payload template placeholders
    ------------------------------
    [host]   -> target_host:target_port
    [crlf]   -> \r\n
    [split]  -> block separator: each block is sent as a distinct HTTP
                request. Intermediate (non-upgrade) responses are fully
                drained before the next block is sent.

    Example two-block payload (CDN-fronted / HTTP smuggling style):

        GET / HTTP/1.1[crlf]Host: front.cdn.com[crlf][crlf]
        [split]
        [crlf][crlf]GET- / HTTP/1.1[crlf]Host: [host][crlf]
        Connection: Upgrade[crlf]Upgrade: Websocket[crlf][crlf]

    Notes
    -----
    * Never reads past the terminal upgrade response, so Paramiko always
      sees the SSH banner as the very first bytes on the socket.
    * Caller owns the socket — call sock.close() when done.
    """
    # ------------------------------------------------------------------ #
    # 1. Connect (or re-use a caller-supplied socket)
    # ------------------------------------------------------------------ #
    if sock is None:
        sock = socket.create_connection((proxy_host, proxy_port))

    if use_tls and not isinstance(sock, ssl.SSLSocket):
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=proxy_host)

    # ------------------------------------------------------------------ #
    # 2. Substitute [host] / [crlf], then split on [split]
    # ------------------------------------------------------------------ #
    payload_bytes = replace_placeholders(payload_template, target_host, target_port)

    raw_blocks = payload_bytes.split(b"[split]")
    blocks = [b.strip(b"\r\n") for b in raw_blocks if b.strip()]

    if not blocks:
        raise ValueError("payload_template produced no sendable blocks")

    # ------------------------------------------------------------------ #
    # 3. Send blocks one at a time; drain intermediate responses
    # ------------------------------------------------------------------ #
    for i, block in enumerate(blocks):
        if not block.endswith(b"\r\n\r\n"):
            block = block + b"\r\n\r\n"

        print(f">> Sending block {i + 1}/{len(blocks)}:\n",
              block.decode("latin1", errors="replace"), flush=True)

        sock.sendall(block)

        response = read_headers(sock)
        print(f">> Response to block {i + 1}:\n",
              response.decode("latin1", errors="replace"), flush=True)

        if _is_upgrade_response(response):
            print("[*] Tunnel established.")
            break

        if b"100 Continue" in response:
            # Server wants more — don't drain, move straight to next block
            continue

        # Intermediate response (301, 302, plain 200, etc.):
        # drain the body so we land at the start of the next HTTP message
        drain_response_body(sock, response)

        if i == len(blocks) - 1:
            raise ConnectionError(
                f"Tunnel upgrade failed after all {len(blocks)} block(s). "
                f"Last response: {response[:200]!r}"
            )

    # ------------------------------------------------------------------ #
    # 4. Return the live socket
    # ------------------------------------------------------------------ #
    print("[*] WebSocket handshake complete – returning raw socket.")
    return sock
