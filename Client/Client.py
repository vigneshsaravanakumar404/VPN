#!/usr/bin/env python3

import socket
import threading
import struct
import select
import json
import os
from datetime import datetime
import re
import sys
import traceback
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

load_dotenv()


class VPNClient:
    def __init__(
        self, server_host, server_port, http_port=8080, socks_port=1080, debug=False
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.http_port = http_port
        self.socks_port = socks_port
        self.connections = 0
        self.debug = debug
        self.total_uploaded = 0
        self.total_downloaded = 0
        self.lock = threading.Lock()

        # Initialize encryption - must match server
        password = os.getenv("VPN_PASSWORD", "change_this_password_immediately")
        salt = b"vpn_salt_2024_change_this"

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        self.encryption_key = kdf.derive(password.encode())

        if self.debug:
            print(f"[DEBUG] Password: '{password[:20]}...'")
            print(f"[DEBUG] Key (hex): {self.encryption_key.hex()[:32]}...")

    def encode_data(self, data):
        """Encrypt data using AES-256-GCM"""
        if not data:
            return data

        try:
            nonce = os.urandom(12)
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(nonce),
                backend=default_backend(),
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            tag = encryptor.tag

            # Pack: [nonce_len][nonce][tag_len][tag][ciphertext]
            encoded = struct.pack("B", len(nonce))
            encoded += nonce
            encoded += struct.pack("B", len(tag))
            encoded += tag
            encoded += ciphertext
            return encoded
        except Exception as e:
            if self.debug:
                print(f"[ERROR] Encryption failed: {e}")
            return None

    def decode_data(self, data):
        """Decrypt data using AES-256-GCM"""
        if not data or len(data) < 2:
            return data

        try:
            offset = 0

            # Extract nonce
            nonce_len = struct.unpack("B", data[offset : offset + 1])[0]
            offset += 1

            if len(data) < offset + nonce_len:
                return None

            nonce = data[offset : offset + nonce_len]
            offset += nonce_len

            # Extract tag
            tag_len = struct.unpack("B", data[offset : offset + 1])[0]
            offset += 1

            if len(data) < offset + tag_len:
                return None

            tag = data[offset : offset + tag_len]
            offset += tag_len

            # Rest is ciphertext
            ciphertext = data[offset:]

            # Decrypt
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(nonce, tag),
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except Exception as e:
            if self.debug:
                print(f"[ERROR] Decryption failed: {e}")
            return None

    def connect_to_server(self):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(5)
            server_socket.connect((self.server_host, self.server_port))
            server_socket.settimeout(None)
            return server_socket
        except Exception as e:
            if self.debug:
                print(f"[ERROR] Cannot connect to server: {e}")
            return None

    def print_stats(self):
        with self.lock:
            up_mb = self.total_uploaded / (1024 * 1024)
            down_mb = self.total_downloaded / (1024 * 1024)
            print(f"\rUp: {up_mb:.2f} MB | Down: {down_mb:.2f} MB", end="", flush=True)

    def start(self):
        print("=" * 50)
        print(f"VPN Client - {self.server_host}:{self.server_port}")
        print(f"HTTP Proxy: localhost:{self.http_port}")
        print(f"SOCKS5 Proxy: localhost:{self.socks_port}")
        print(f"Encryption: AES-256-GCM")
        print("=" * 50)

        password = os.getenv("VPN_PASSWORD", "change_this_password_immediately")
        if password == "change_this_password_immediately":
            print("⚠️  WARNING: Using default password!")
            print("   Set: $env:VPN_PASSWORD = 'YourPassword'")
        else:
            print(f"✓ Password set ({len(password)} chars)")
        print()

        # Test server connection
        test_socket = self.connect_to_server()
        if test_socket:
            print(f"✓ Connected to server")
            test_socket.close()
        else:
            print(f"✗ Cannot connect to {self.server_host}:{self.server_port}")
            print("  Check server is running with same password")
            return

        print("Starting proxy servers...")

        # Start proxy threads
        http_thread = threading.Thread(target=self.start_http_proxy)
        http_thread.daemon = True
        http_thread.start()

        socks_thread = threading.Thread(target=self.start_socks5_proxy)
        socks_thread.daemon = True
        socks_thread.start()

        stats_thread = threading.Thread(target=self.stats_printer)
        stats_thread.daemon = True
        stats_thread.start()

        print("Ready for connections!")
        print()

        try:
            while True:
                threading.Event().wait(1)
        except KeyboardInterrupt:
            print("\n\nShutting down...")

    def stats_printer(self):
        while True:
            threading.Event().wait(1)
            self.print_stats()

    def start_http_proxy(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind(("0.0.0.0", self.http_port))
            server.listen(50)

            while True:
                client, addr = server.accept()
                self.connections += 1
                thread = threading.Thread(
                    target=self.handle_http_client,
                    args=(client, addr, self.connections),
                )
                thread.daemon = True
                thread.start()

        except Exception as e:
            print(f"HTTP proxy error: {e}")
        finally:
            server.close()

    def start_socks5_proxy(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind(("127.0.0.1", self.socks_port))
            server.listen(50)

            while True:
                client, addr = server.accept()
                self.connections += 1
                thread = threading.Thread(
                    target=self.handle_socks5_client,
                    args=(client, addr, self.connections),
                )
                thread.daemon = True
                thread.start()

        except Exception as e:
            print(f"SOCKS5 proxy error: {e}")
        finally:
            server.close()

    def send_handshake(self, server_socket, tunnel_request):
        """Send initial handshake packet to server"""
        # Convert request to JSON
        tunnel_json = json.dumps(tunnel_request).encode("utf-8")

        # Encrypt the JSON
        encrypted_packet = self.encode_data(tunnel_json)
        if not encrypted_packet:
            return False

        # Send with length prefix
        packet_length = struct.pack("!I", len(encrypted_packet))
        server_socket.send(packet_length + encrypted_packet)
        return True

    def handle_http_client(self, client, addr, conn_num):
        try:
            client.settimeout(10)

            # Read HTTP request
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

            try:
                request = request_data.decode("utf-8")
            except:
                request = request_data.decode("latin-1")

            lines = request.split("\n")
            if not lines:
                client.close()
                return

            first_line = lines[0].strip()

            # Parse request
            tunnel_request = {
                "protocol": "HTTP",
                "method": first_line.split(" ")[0] if " " in first_line else "GET",
                "is_connect": first_line.startswith("CONNECT"),
            }

            if first_line.startswith("CONNECT"):
                # HTTPS CONNECT request
                url = first_line.split(" ")[1]
                if ":" in url:
                    host, port = url.split(":")
                    port = int(port)
                else:
                    host = url
                    port = 443
                tunnel_request["host"] = host
                tunnel_request["port"] = port
            else:
                # Regular HTTP request
                host_match = re.search(r"Host: (.+)\r?\n", request)
                if not host_match:
                    client.close()
                    return

                host = host_match.group(1).strip()
                port = 80

                if ":" in host:
                    host, port = host.split(":")
                    port = int(port)

                tunnel_request["host"] = host
                tunnel_request["port"] = port
                tunnel_request["request"] = request

            if self.debug:
                print(f"\n[HTTP {conn_num}] {tunnel_request['method']} {host}:{port}")

            # Connect to VPN server
            server_socket = self.connect_to_server()
            if not server_socket:
                client.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                client.close()
                return

            # Send handshake
            if not self.send_handshake(server_socket, tunnel_request):
                if self.debug:
                    print(f"[HTTP {conn_num}] Handshake failed")
                server_socket.close()
                client.close()
                return

            # Send 200 OK for CONNECT method
            if tunnel_request["is_connect"]:
                client.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            # Relay data
            self.relay_tunnel_data(client, server_socket, conn_num)

        except Exception as e:
            if self.debug:
                print(f"[HTTP {conn_num}] Error: {e}")
        finally:
            client.close()

    def handle_socks5_client(self, client, addr, conn_num):
        try:
            # SOCKS5 greeting
            greeting = client.recv(2)
            if not greeting or greeting[0] != 5:
                client.close()
                return

            n_methods = greeting[1]
            methods = client.recv(n_methods)

            # No authentication
            client.send(b"\x05\x00")

            # Connection request
            request = client.recv(4)
            if not request or len(request) < 4:
                client.close()
                return

            version, cmd, _, addr_type = struct.unpack("!BBBB", request)

            if cmd != 1:  # Only CONNECT
                client.send(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                client.close()
                return

            # Parse target address
            target_addr = None
            if addr_type == 1:  # IPv4
                addr_bytes = client.recv(4)
                if addr_bytes:
                    target_addr = socket.inet_ntoa(addr_bytes)
            elif addr_type == 3:  # Domain
                domain_len = client.recv(1)[0]
                domain_bytes = client.recv(domain_len)
                if domain_bytes:
                    target_addr = domain_bytes.decode("utf-8")
            elif addr_type == 4:  # IPv6
                addr_bytes = client.recv(16)
                if addr_bytes:
                    target_addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)

            # Get port
            port_bytes = client.recv(2)
            if port_bytes:
                target_port = struct.unpack("!H", port_bytes)[0]
            else:
                client.close()
                return

            if not target_addr:
                client.close()
                return

            if self.debug:
                print(f"\n[SOCKS5 {conn_num}] Connect to {target_addr}:{target_port}")

            # Connect to VPN server
            server_socket = self.connect_to_server()
            if not server_socket:
                client.send(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                client.close()
                return

            # Send handshake
            tunnel_request = {
                "protocol": "SOCKS5",
                "host": target_addr,
                "port": target_port,
                "addr_type": addr_type,
            }

            if not self.send_handshake(server_socket, tunnel_request):
                if self.debug:
                    print(f"[SOCKS5 {conn_num}] Handshake failed")
                client.send(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                server_socket.close()
                client.close()
                return

            # Wait for server response
            response = server_socket.recv(1)
            if response == b"\x00":
                # Success
                reply = b"\x05\x00\x00\x01"
                reply += socket.inet_aton("0.0.0.0")
                reply += struct.pack("!H", 0)
                client.send(reply)

                # Relay data
                self.relay_tunnel_data(client, server_socket, conn_num)
            else:
                # Failed
                client.send(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                server_socket.close()

        except Exception as e:
            if self.debug:
                print(f"[SOCKS5 {conn_num}] Error: {e}")
        finally:
            client.close()

    def relay_tunnel_data(self, client, server, conn_num):
        """Relay data between browser and VPN server with proper framing"""

        # Buffer for partial packets from server
        server_buffer = b""

        try:
            while True:
                readers, _, _ = select.select([client, server], [], [], 1)

                # Data from browser (plaintext)
                if client in readers:
                    data = client.recv(4096)
                    if not data:
                        break

                    # Encrypt and send to server
                    encrypted = self.encode_data(data)
                    if encrypted:
                        # Send with length prefix
                        length_prefix = struct.pack("!I", len(encrypted))
                        server.send(length_prefix + encrypted)

                        with self.lock:
                            self.total_uploaded += len(data)
                    else:
                        if self.debug:
                            print(f"[Conn {conn_num}] Encryption failed")
                        return

                # Data from VPN server (encrypted)
                if server in readers:
                    chunk = server.recv(4096)
                    if not chunk:
                        break

                    server_buffer += chunk

                    # Process complete packets from buffer
                    while len(server_buffer) >= 4:
                        # Check if we have the length header
                        packet_length = struct.unpack("!I", server_buffer[:4])[0]

                        # Check for invalid packet length
                        if packet_length > 1024 * 1024:
                            if self.debug:
                                print(
                                    f"[Conn {conn_num}] Invalid packet length: {packet_length}"
                                )
                            return

                        # Check if we have the complete packet
                        if len(server_buffer) >= 4 + packet_length:
                            # Extract the complete packet
                            encrypted_data = server_buffer[4 : 4 + packet_length]
                            server_buffer = server_buffer[4 + packet_length :]

                            # Decrypt and forward to browser
                            decrypted = self.decode_data(encrypted_data)
                            if decrypted:
                                client.send(decrypted)
                                with self.lock:
                                    self.total_downloaded += len(decrypted)
                            else:
                                if self.debug:
                                    print(f"[Conn {conn_num}] Decryption failed")
                                return
                        else:
                            # Need more data
                            break

        except Exception as e:
            if self.debug:
                print(f"[Conn {conn_num}] Relay error: {e}")
        finally:
            try:
                client.close()
            except:
                pass
            try:
                server.close()
            except:
                pass


def main():
    server_host = os.getenv("VPN_SERVER_HOST", "localhost")
    server_port = int(os.getenv("VPN_SERVER_PORT", "9999"))

    debug = "--debug" in sys.argv or "-d" in sys.argv

    http_port = 8080
    socks_port = 1080

    # Parse command line arguments
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
        http_port=http_port,
        socks_port=socks_port,
        debug=debug,
    )

    try:
        client.start()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
