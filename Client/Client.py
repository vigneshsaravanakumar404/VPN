#!/usr/bin/env python3
"""
VPN Client - Minimal output version with auto-generated encryption
"""

import socket
import threading
import struct
import select
import json
import os
import sys
import time
from datetime import datetime


class VPNClient:
    def __init__(
        self, server_host, server_port, local_http_port=8080, local_socks_port=1080
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.local_http_port = local_http_port
        self.local_socks_port = local_socks_port
        self.total_uploaded = 0
        self.total_downloaded = 0
        self.encryption_key = None
        self.connected = False
        self.lock = threading.Lock()

    def encode_data(self, data):
        """XOR encode data with server-provided key"""
        if not self.encryption_key:
            return data
        encoded = bytearray()
        for i, byte in enumerate(data):
            encoded.append(byte ^ self.encryption_key[i % len(self.encryption_key)])
        return bytes(encoded)

    def decode_data(self, data):
        """XOR decode data with server-provided key"""
        return self.encode_data(data)  # XOR is symmetric

    def connect_to_server(self):
        """Create connection to VPN server and get encryption key"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10)
            server_socket.connect((self.server_host, self.server_port))
            server_socket.settimeout(None)

            # Receive encryption key from server (first connection)
            if not self.encryption_key:
                key_length = struct.unpack("!I", server_socket.recv(4))[0]
                self.encryption_key = server_socket.recv(key_length)
                self.connected = True

            return server_socket
        except:
            return None

    def send_request_to_server(
        self, request_type, target_host, target_port, initial_data=None
    ):
        """Send request to VPN server"""
        server_socket = self.connect_to_server()
        if not server_socket:
            return None

        try:
            # Create request packet
            request = {"type": request_type, "host": target_host, "port": target_port}

            # Send request
            request_json = json.dumps(request).encode("utf-8")
            header = struct.pack("!I", len(request_json))

            encoded_header = self.encode_data(header + request_json)
            server_socket.send(encoded_header)

            # Wait for acknowledgment
            response = server_socket.recv(1)
            if response != b"\x00":
                server_socket.close()
                return None

            # Send initial data if provided
            if initial_data:
                encoded_data = self.encode_data(initial_data)
                server_socket.send(struct.pack("!I", len(encoded_data)))
                server_socket.send(encoded_data)

            return server_socket

        except:
            server_socket.close()
            return None

    def update_stats(self):
        """Update and display statistics"""
        with self.lock:
            # Clear line and print stats
            up_mb = self.total_uploaded / (1024 * 1024)
            down_mb = self.total_downloaded / (1024 * 1024)
            status = "Connected" if self.connected else "Connecting..."
            print(
                f"\r{status} | Up: {up_mb:.2f} MB | Down: {down_mb:.2f} MB",
                end="",
                flush=True,
            )

    def start(self):
        """Start proxy servers"""
        # Start HTTP proxy thread
        http_thread = threading.Thread(target=self.start_http_proxy)
        http_thread.daemon = True
        http_thread.start()

        # Start SOCKS5 proxy thread
        socks_thread = threading.Thread(target=self.start_socks5_proxy)
        socks_thread.daemon = True
        socks_thread.start()

        # Stats update thread
        stats_thread = threading.Thread(target=self.stats_updater)
        stats_thread.daemon = True
        stats_thread.start()

        print(
            f"VPN Client: localhost:{self.local_http_port} (HTTP) | localhost:{self.local_socks_port} (SOCKS5)"
        )

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutdown")

    def stats_updater(self):
        """Update stats display periodically"""
        while True:
            self.update_stats()
            time.sleep(1)

    def start_http_proxy(self):
        """Start local HTTP proxy server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind(("127.0.0.1", self.local_http_port))
            server.listen(50)

            while True:
                client, addr = server.accept()
                thread = threading.Thread(
                    target=self.handle_http_client, args=(client,)
                )
                thread.daemon = True
                thread.start()
        except:
            pass
        finally:
            server.close()

    def start_socks5_proxy(self):
        """Start local SOCKS5 proxy server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind(("127.0.0.1", self.local_socks_port))
            server.listen(50)

            while True:
                client, addr = server.accept()
                thread = threading.Thread(
                    target=self.handle_socks5_client, args=(client,)
                )
                thread.daemon = True
                thread.start()
        except:
            pass
        finally:
            server.close()

    def handle_http_client(self, client):
        """Handle HTTP proxy client"""
        try:
            client.settimeout(10)

            # Receive HTTP request
            request_data = b""
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                request_data += chunk
                if b"\r\n\r\n" in request_data:
                    break

            client.settimeout(None)

            if not request_data:
                client.close()
                return

            request = request_data.decode("utf-8", errors="ignore")
            lines = request.split("\n")
            if not lines:
                client.close()
                return

            first_line = lines[0].strip()

            if first_line.startswith("CONNECT"):
                # HTTPS tunnel
                url = first_line.split(" ")[1]
                if ":" in url:
                    host, port = url.split(":")
                    port = int(port)
                else:
                    host = url
                    port = 443

                server_socket = self.send_request_to_server("HTTPS", host, port)
                if not server_socket:
                    client.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    return

                client.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self.relay_encrypted_data(client, server_socket)

            else:
                # HTTP request
                import re

                host_match = re.search(r"Host: (.+)\r?\n", request)
                if not host_match:
                    client.close()
                    return

                host = host_match.group(1).strip()
                port = 80

                if ":" in host:
                    host, port = host.split(":")
                    port = int(port)

                server_socket = self.send_request_to_server(
                    "HTTP", host, port, request_data
                )
                if not server_socket:
                    client.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    return

                self.relay_encrypted_data(client, server_socket)

        except:
            pass
        finally:
            try:
                client.close()
            except:
                pass

    def handle_socks5_client(self, client):
        """Handle SOCKS5 client"""
        try:
            # SOCKS5 handshake
            greeting = client.recv(2)
            if not greeting or len(greeting) < 2 or greeting[0] != 5:
                client.close()
                return

            n_methods = greeting[1]
            methods = client.recv(n_methods)
            client.send(b"\x05\x00")

            # Connection request
            request = client.recv(4)
            if not request or len(request) < 4:
                client.close()
                return

            version, cmd, _, addr_type = struct.unpack("!BBBB", request)

            if cmd != 1:
                reply = b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00"
                client.send(reply)
                client.close()
                return

            # Parse address
            target_addr, target_port = self.parse_socks5_address(client, addr_type)
            if not target_addr or target_port is None:
                reply = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"
                client.send(reply)
                client.close()
                return

            # Connect through VPN
            server_socket = self.send_request_to_server(
                "SOCKS5", target_addr, target_port
            )
            if not server_socket:
                reply = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"
                client.send(reply)
                return

            # Success response
            reply = (
                b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0)
            )
            client.send(reply)

            self.relay_encrypted_data(client, server_socket)

        except:
            pass
        finally:
            try:
                client.close()
            except:
                pass

    def parse_socks5_address(self, client, addr_type):
        """Parse SOCKS5 target address"""
        target_addr = None
        target_port = None

        try:
            if addr_type == 1:  # IPv4
                addr_bytes = client.recv(4)
                if addr_bytes and len(addr_bytes) == 4:
                    target_addr = socket.inet_ntoa(addr_bytes)

            elif addr_type == 3:  # Domain
                domain_length_bytes = client.recv(1)
                if domain_length_bytes:
                    domain_length = domain_length_bytes[0]
                    domain_bytes = client.recv(domain_length)
                    if domain_bytes and len(domain_bytes) == domain_length:
                        target_addr = domain_bytes.decode("utf-8")

            elif addr_type == 4:  # IPv6
                addr_bytes = client.recv(16)
                if addr_bytes and len(addr_bytes) == 16:
                    target_addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)

            if target_addr:
                port_bytes = client.recv(2)
                if port_bytes and len(port_bytes) == 2:
                    target_port = struct.unpack("!H", port_bytes)[0]

        except:
            pass

        return target_addr, target_port

    def relay_encrypted_data(self, client, server_socket):
        """Relay data between client and VPN server"""
        try:
            while True:
                try:
                    readers, _, _ = select.select([client, server_socket], [], [], 1)

                    if client in readers:
                        data = client.recv(4096)
                        if not data:
                            break

                        # Encode and send to server
                        encoded_data = self.encode_data(data)
                        server_socket.send(struct.pack("!I", len(encoded_data)))
                        server_socket.send(encoded_data)

                        with self.lock:
                            self.total_uploaded += len(data)

                    if server_socket in readers:
                        # Read length prefix
                        length_bytes = server_socket.recv(4)
                        if not length_bytes or len(length_bytes) < 4:
                            break

                        length = struct.unpack("!I", length_bytes)[0]

                        # Read encoded data
                        encoded_data = b""
                        while len(encoded_data) < length:
                            chunk = server_socket.recv(
                                min(4096, length - len(encoded_data))
                            )
                            if not chunk:
                                break
                            encoded_data += chunk

                        if len(encoded_data) < length:
                            break

                        # Decode and send to client
                        data = self.decode_data(encoded_data)
                        client.send(data)

                        with self.lock:
                            self.total_downloaded += len(data)

                except socket.error:
                    break
                except:
                    break

        finally:
            try:
                client.close()
            except:
                pass
            try:
                server_socket.close()
            except:
                pass


def main():
    # Get server details from args or defaults
    server_host = "localhost"
    server_port = 8888
    http_port = 8080
    socks_port = 1080

    for i, arg in enumerate(sys.argv):
        if arg == "--server" and i + 1 < len(sys.argv):
            server_host = sys.argv[i + 1]
        elif arg == "--server-port" and i + 1 < len(sys.argv):
            try:
                server_port = int(sys.argv[i + 1])
            except:
                pass
        elif arg == "--http-port" and i + 1 < len(sys.argv):
            try:
                http_port = int(sys.argv[i + 1])
            except:
                pass
        elif arg == "--socks-port" and i + 1 < len(sys.argv):
            try:
                socks_port = int(sys.argv[i + 1])
            except:
                pass

    client = VPNClient(
        server_host=server_host,
        server_port=server_port,
        local_http_port=http_port,
        local_socks_port=socks_port,
    )

    try:
        client.start()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
