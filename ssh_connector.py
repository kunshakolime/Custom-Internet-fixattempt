import socket
import threading
import paramiko
import struct

class SSHOverWebSocket:
    """
    Wraps a Paramiko Transport (SSH) that runs on top of a raw
    WebSocket-upgraded socket, plus a local SOCKS server.
    """

    def __init__(self, ws_socket, ssh_username, ssh_password):
        self.ws_socket = ws_socket
        self.ssh_username = ssh_username
        self.ssh_password = ssh_password
        self.transport = None

    def start_ssh_transport(self):
        self.transport = paramiko.Transport(self.ws_socket)
        self.transport.start_client()
        self.transport.auth_password(self.ssh_username, self.ssh_password)
        if not self.transport.is_authenticated():
            raise Exception("SSH Authentication failed")

        print("[*] SSH transport established and authenticated.")

    def close(self):
        """ Clean up. """
        if self.transport is not None:
            self.transport.close()

    def open_socks_proxy(self, local_port):
        """
        Start a small SOCKS4/5 server on local_port that forwards
        connections through the SSH transport.

        The user can configure their browser or app to use
        127.0.0.1:local_port as a SOCKS proxy.
        """
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', local_port))
        server.listen(100)
        print(f"[*] SOCKS proxy listening on 127.0.0.1:{local_port}")

        def handle_socks_client(client_sock):
            try:
                # Peek the first byte to determine if it's SOCKS4 or SOCKS5.
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
                    print("[!] Unsupported SOCKS version.")
                    client_sock.close()

            except Exception as e:
                print(f"[!] SOCKS client error: {e}")
                client_sock.close()

        def accept_loop():
            while True:
                try:
                    client_sock, _ = server.accept()
                    threading.Thread(target=handle_socks_client,
                                     args=(client_sock,),
                                     daemon=True).start()
                except:
                    break

        threading.Thread(target=accept_loop, daemon=True).start()
        print("[*] SOCKS proxy started.")

    def _forward_data(self, src, dst):
        """Helper: forward data from src -> dst until EOF."""
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
        try:
            chan = self.transport.open_channel(
                "direct-tcpip",
                (host, port),
                client_sock.getsockname()
            )
        except paramiko.ChannelException as e:
            client_sock.close()
            return
        threading.Thread(target=self._forward_data, args=(client_sock, chan), daemon=True).start()
        threading.Thread(target=self._forward_data, args=(chan, client_sock), daemon=True).start()

    def _handle_socks4(self, client_sock):
        """
        Handle a SOCKS4 or SOCKS4a request.
        """
        # The client already sent 1 byte for version. We'll read the rest.
        # Typical SOCKS4 layout:
        # byte[0] = 0x04 (version)
        # byte[1] = command (1=connect)
        # byte[2:4] = port (big-endian)
        # byte[4:8] = IP (if 0.0.0.x => maybe SOCKS4a)
        # then a null-terminated userID
        # if IP is 0.0.0.x => we read the domain after userID, also null-terminated
        try:
            header = self._recv_exactly(client_sock, 8)
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
                # only CONNECT is supported
                # error response
                resp = b"\x00\x5B\x00\x00\x00\x00\x00\x00"  # Request rejected
                client_sock.sendall(resp)
                client_sock.close()
                return

            # respond with "granted"
            resp = b"\x00\x5A" + data[2:4] + data[4:8]
            client_sock.sendall(resp)

            # Now open SSH channel
            self._open_ssh_channel(client_sock, host, port)

        except Exception as e:
            print(f"[!] SOCKS4 error: {e}")
            client_sock.close()

    def _handle_socks5(self, client_sock):
        """
        Handle a SOCKS5 request with basic "no auth" only, plus CONNECT command.
        """
        # Step 1: Method negotiation
        #   +----+----------+----------+
        #   |VER | NMETHODS | METHODS  |
        #   +----+----------+----------+
        #   | 1  |    1     | 1-255    |
        #   +----+----------+----------+
        try:
            # First read the initial packet fully to get the number of methods
            ver_nmethods = client_sock.recv(2)
            if len(ver_nmethods) < 2:
                client_sock.close()
                return

            version, nmethods = ver_nmethods[0], ver_nmethods[1]
            if version != 5:
                client_sock.close()
                return

            methods = client_sock.recv(nmethods)
            # We won't check if 0x00 "no auth" is in there; we just pick no auth.
            # Send our chosen method = 0x00 (no auth)
            client_sock.sendall(b"\x05\x00")

            # Step 2: Client sends a connection request:
            #   +----+-----+-------+------+----------+----------+
            #   |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            #   +----+-----+-------+------+----------+----------+
            #   | 1  |  1  | X'00' |  1   | Variable |    2     |
            #   +----+-----+-------+------+----------+----------+

            request_hdr = client_sock.recv(4)
            if len(request_hdr) < 4:
                client_sock.close()
                return

            req_ver, cmd, rsv, atyp = request_hdr

            # We only support CONNECT
            if cmd != 0x01:
                # send error
                self._send_socks5_error(client_sock, 0x07)  # X'07' = Command not supported
                return

            # Parse address
            if atyp == 0x01:
                # IPv4
                addr = client_sock.recv(4)
                host = socket.inet_ntoa(addr)
            elif atyp == 0x03:
                # Domain
                domain_len = client_sock.recv(1)[0]
                domain = client_sock.recv(domain_len)
                host = domain.decode('utf-8', errors='replace')
            elif atyp == 0x04:
                # IPv6
                addr = client_sock.recv(16)
                # interpret as IPv6 address
                host = socket.inet_ntop(socket.AF_INET6, addr)
            else:
                self._send_socks5_error(client_sock, 0x08)  # address type not supported
                return

            # Next 2 bytes is port
            port_bytes = client_sock.recv(2)
            if len(port_bytes) < 2:
                client_sock.close()
                return
            port = struct.unpack('>H', port_bytes)[0]

            # Step 3: respond "success" if we can attempt to connect
            self._send_socks5_success(client_sock)

            # Step 4: open SSH channel
            self._open_ssh_channel(client_sock, host, port)

        except Exception as e:
            print(f"[!] SOCKS5 error: {e}")
            client_sock.close()

    def _send_socks5_error(self, client_sock, err_code):
        """
        Send a SOCKS5 error reply and close.
        err_code is a single byte, e.g.:
           0x01 = general failure
           0x05 = connection refused
           0x07 = cmd not supported
           0x08 = addr type not supported
        """
        # Minimal "fail" response: VER=5, REP=err_code, RSV=0, ATYP=1 (IPv4), BND.ADDR=0.0.0.0, BND.PORT=0
        reply = b"\x05" + bytes([err_code]) + b"\x00\x01\x00\x00\x00\x00\x00\x00"
        client_sock.sendall(reply)
        client_sock.close()

    def _send_socks5_success(self, client_sock):
        """
        Send a SOCKS5 'connection granted' response with a dummy bind address.
        """
        # VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR=0.0.0.0, BND.PORT=0
        success = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        client_sock.sendall(success)

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
    # Keep the object in scope so it’s not garbage-collected
    return connector
