import logging
import socket
import threading
import paramiko
import struct

# Suppress Paramiko's built-in channel failure messages — we handle errors ourselves
logging.getLogger("paramiko").setLevel(logging.CRITICAL)


class SSHOverWebSocket:
    """
    Wraps a Paramiko Transport (SSH) that runs on top of a raw
    WebSocket-upgraded socket, plus a local SOCKS server.
    """

    def __init__(self, ws_socket, ssh_username, ssh_password):
        self.ws_socket    = ws_socket
        self.ssh_username = ssh_username
        self.ssh_password = ssh_password
        self.transport    = None

    def start_ssh_transport(self):
        self.transport = paramiko.Transport(self.ws_socket)
        self.transport.set_keepalive(60)
        self.transport.start_client()
        self.transport.auth_password(self.ssh_username, self.ssh_password)
        if not self.transport.is_authenticated():
            raise Exception("SSH Authentication failed")
        print("[*] SSH transport established and authenticated.")

    def close(self):
        if self.transport is not None:
            self.transport.close()

    def open_socks_proxy(self, local_port):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', local_port))
        server.listen(100)
        print(f"[*] SOCKS proxy listening on 127.0.0.1:{local_port}")

        def handle_socks_client(client_sock):
            try:
                initial = client_sock.recv(1, socket.MSG_PEEK)
                if not initial:
                    client_sock.close()
                    return
                ver = initial[0]
                if ver == 4:
                    self._handle_socks4(client_sock)
                elif ver == 5:
                    self._handle_socks5(client_sock)
                else:
                    client_sock.close()
            except Exception as e:
                print(f"[!] SOCKS client error: {e}")
                client_sock.close()

        def accept_loop():
            while True:
                try:
                    client_sock, _ = server.accept()
                    threading.Thread(target=handle_socks_client,
                                     args=(client_sock,), daemon=True).start()
                except:
                    break

        threading.Thread(target=accept_loop, daemon=True).start()
        print("[*] SOCKS proxy started.")

    # ---------------------------------------------------------------------- #
    #                            Data forwarding                             #
    # ---------------------------------------------------------------------- #

    def _forward_data(self, src, dst):
        """Forward data from src -> dst until EOF."""
        try:
            while True:
                chunk = src.recv(4096)
                if not chunk:
                    break
                dst.sendall(chunk)
        except:
            pass
        finally:
            dst.close()
            src.close()

    def _open_ssh_channel(self, client_sock, host, port):
        """Open a direct-tcpip SSH channel and forward bidirectionally."""
        try:
            chan = self.transport.open_channel(
                "direct-tcpip",
                (host, port),
                client_sock.getsockname()
            )
        except paramiko.ChannelException:
            client_sock.close()
            return
        threading.Thread(target=self._forward_data, args=(client_sock, chan), daemon=True).start()
        threading.Thread(target=self._forward_data, args=(chan, client_sock), daemon=True).start()

    # ---------------------------------------------------------------------- #
    #                           SOCKS4 handler                               #
    # ---------------------------------------------------------------------- #

    def _handle_socks4(self, client_sock):
        try:
            header  = self._recv_exactly(client_sock, 8)
            cmd     = header[1]
            port    = struct.unpack('>H', header[2:4])[0]
            ip_part = header[4:8]
            host    = socket.inet_ntoa(ip_part)

            # consume null-terminated userID
            while client_sock.recv(1) not in (b'\x00', b''):
                pass

            # SOCKS4a: IP is 0.0.0.x → domain follows userID
            if ip_part[:3] == b'\x00\x00\x00' and ip_part[3] != 0:
                domain = bytearray()
                while True:
                    b = client_sock.recv(1)
                    if b in (b'\x00', b''):
                        break
                    domain += b
                host = domain.decode('utf-8', errors='replace')

            if cmd != 1:
                client_sock.sendall(b"\x00\x5B\x00\x00\x00\x00\x00\x00")
                client_sock.close()
                return

            client_sock.sendall(b"\x00\x5A" + header[2:4] + header[4:8])
            self._open_ssh_channel(client_sock, host, port)

        except Exception as e:
            print(f"[!] SOCKS4 error: {e}")
            client_sock.close()

    # ---------------------------------------------------------------------- #
    #                           SOCKS5 handler                               #
    # ---------------------------------------------------------------------- #

    def _handle_socks5(self, client_sock):
        try:
            ver_nmethods = client_sock.recv(2)
            if len(ver_nmethods) < 2 or ver_nmethods[0] != 5:
                client_sock.close()
                return

            client_sock.recv(ver_nmethods[1])       # discard method list
            client_sock.sendall(b"\x05\x00")        # no auth

            request_hdr = client_sock.recv(4)
            if len(request_hdr) < 4:
                client_sock.close()
                return

            _, cmd, _, atyp = request_hdr

            # Parse destination address
            if atyp == 0x01:
                host = socket.inet_ntoa(client_sock.recv(4))
            elif atyp == 0x03:
                dlen = client_sock.recv(1)[0]
                host = client_sock.recv(dlen).decode('utf-8', errors='replace')
            elif atyp == 0x04:
                host = socket.inet_ntop(socket.AF_INET6, client_sock.recv(16))
            else:
                self._send_socks5_error(client_sock, 0x08)
                return

            port_bytes = client_sock.recv(2)
            if len(port_bytes) < 2:
                client_sock.close()
                return
            port = struct.unpack('>H', port_bytes)[0]

            if cmd == 0x01:
                self._send_socks5_success(client_sock)
                self._open_ssh_channel(client_sock, host, port)
            else:
                self._send_socks5_error(client_sock, 0x07)

        except Exception as e:
            print(f"[!] SOCKS5 error: {e}")
            client_sock.close()

    def _send_socks5_error(self, client_sock, err_code):
        reply = b"\x05" + bytes([err_code]) + b"\x00\x01\x00\x00\x00\x00\x00\x00"
        client_sock.sendall(reply)
        client_sock.close()

    def _send_socks5_success(self, client_sock):
        client_sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

    def _recv_exactly(self, sock, n: int) -> bytes:
        """Read exactly n bytes, raising if the connection closes early."""
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Socket closed during SOCKS handshake")
            buf += chunk
        return buf


def connect_via_ws_and_start_socks(ws_socket, ssh_user, ssh_password, local_socks_port):
    """Start SSH transport over ws_socket and open a local SOCKS proxy."""
    connector = SSHOverWebSocket(ws_socket, ssh_user, ssh_password)
    connector.start_ssh_transport()
    connector.open_socks_proxy(local_socks_port)
    return connector
