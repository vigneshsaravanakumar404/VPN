#!/usr/bin/env python3
"""
VPN Client Core
Handles all VPN connection and proxy server functionality
"""

import socket
import struct
import os
import threading
from select import select
from re import search
from json import dumps
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from config import *


class VPNClient:
    """Core VPN client functionality"""

    def __init__(
        self,
        server_host=VPN_SERVER,
        server_port=VPN_PORT,
        http_port=HTTP_PROXY_PORT,
        socks_port=SOCKS_PROXY_PORT,
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.http_port = http_port
        self.socks_port = socks_port
        self.total_uploaded = 0
        self.total_downloaded = 0
        self.active = False
        self.stop_event = threading.Event()
        self.lock = threading.Lock()

        # Initialize encryption
        self._initialize_encryption()

    def _initialize_encryption(self):
        """Initialize encryption key"""
        password = os.getenv("VPN_PASSWORD", VPN_PASSWORD)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=ENCRYPTION_SALT,
            iterations=ENCRYPTION_ITERATIONS,
            backend=default_backend(),
        )
        self.encryption_key = kdf.derive(password.encode())

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

            encoded = struct.pack("B", len(nonce))
            encoded += nonce
            encoded += struct.pack("B", len(tag))
            encoded += tag
            encoded += ciphertext
            return encoded
        except:
            return None

    def decode_data(self, data):
        """Decrypt data using AES-256-GCM"""
        if not data or len(data) < 2:
            return data

        try:
            offset = 0
            nonce_len = struct.unpack("B", data[offset : offset + 1])[0]
            offset += 1

            if len(data) < offset + nonce_len:
                return None

            nonce = data[offset : offset + nonce_len]
            offset += nonce_len

            tag_len = struct.unpack("B", data[offset : offset + 1])[0]
            offset += 1

            if len(data) < offset + tag_len:
                return None

            tag = data[offset : offset + tag_len]
            offset += tag_len

            ciphertext = data[offset:]

            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(nonce, tag),
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except:
            return None

    def connect_to_server(self):
        """Connect to VPN server"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(CONNECTION_TIMEOUT)
            server_socket.connect((self.server_host, self.server_port))
            server_socket.settimeout(None)
            return server_socket
        except:
            return None

    def test_connection(self):
        """Test connection to VPN server"""
        sock = self.connect_to_server()
        if sock:
            sock.close()
            return True
        return False

    def reset_stats(self):
        """Reset session statistics"""
        with self.lock:
            self.total_uploaded = 0
            self.total_downloaded = 0

    def get_stats(self):
        """Get current statistics"""
        with self.lock:
            return self.total_uploaded, self.total_downloaded

    def start(self):
        """Start VPN proxy servers"""
        self.stop_event.clear()
        self.active = True
        self.reset_stats()

        # Start proxy threads
        threading.Thread(target=self.start_http_proxy, daemon=True).start()
        threading.Thread(target=self.start_socks5_proxy, daemon=True).start()

    def stop(self):
        """Stop VPN proxy servers"""
        self.active = False
        self.stop_event.set()

    def start_http_proxy(self):
        """Run HTTP proxy server"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.settimeout(SOCKET_TIMEOUT)
            server.bind((PROXY_LISTEN_ADDRESS, self.http_port))
            server.listen(PROXY_LISTEN_BACKLOG)

            while not self.stop_event.is_set():
                try:
                    client, addr = server.accept()
                    if not self.stop_event.is_set():
                        threading.Thread(
                            target=self.handle_http_client,
                            args=(client, addr),
                            daemon=True,
                        ).start()
                except socket.timeout:
                    continue
                except:
                    break

            server.close()
        except:
            pass

    def start_socks5_proxy(self):
        """Run SOCKS5 proxy server"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.settimeout(SOCKET_TIMEOUT)
            server.bind((SOCKS_LISTEN_ADDRESS, self.socks_port))
            server.listen(PROXY_LISTEN_BACKLOG)

            while not self.stop_event.is_set():
                try:
                    client, addr = server.accept()
                    if not self.stop_event.is_set():
                        threading.Thread(
                            target=self.handle_socks5_client,
                            args=(client, addr),
                            daemon=True,
                        ).start()
                except socket.timeout:
                    continue
                except:
                    break

            server.close()
        except:
            pass

    def send_handshake(self, server_socket, tunnel_request):
        """Send initial handshake packet to server"""
        tunnel_json = dumps(tunnel_request).encode("utf-8")
        encrypted_packet = self.encode_data(tunnel_json)

        if not encrypted_packet:
            return False

        packet_length = struct.pack("!I", len(encrypted_packet))
        server_socket.send(packet_length + encrypted_packet)
        return True

    def handle_http_client(self, client, addr):
        """Handle HTTP client connection"""
        try:
            client.settimeout(CLIENT_TIMEOUT)

            request_data = b""
            while True:
                chunk = client.recv(BUFFER_SIZE)
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

            tunnel_request = {
                "protocol": "HTTP",
                "method": first_line.split(" ")[0] if " " in first_line else "GET",
                "is_connect": first_line.startswith("CONNECT"),
            }

            if first_line.startswith("CONNECT"):
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
                host_match = search(r"Host: (.+)\r?\n", request)
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

            server_socket = self.connect_to_server()
            if not server_socket:
                client.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                client.close()
                return

            if not self.send_handshake(server_socket, tunnel_request):
                server_socket.close()
                client.close()
                return

            if tunnel_request["is_connect"]:
                client.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            self.relay_tunnel_data(client, server_socket)

        except:
            pass
        finally:
            try:
                client.close()
            except:
                pass

    def handle_socks5_client(self, client, addr):
        """Handle SOCKS5 client connection"""
        # TODO: Implement SOCKS5 handling
        # This is a placeholder - full implementation would go here
        pass

    def relay_tunnel_data(self, client, server):
        """Relay data between browser and VPN server"""
        server_buffer = b""

        try:
            while True:
                readers, _, _ = select([client, server], [], [], 1)

                if client in readers:
                    data = client.recv(BUFFER_SIZE)
                    if not data:
                        break

                    encrypted = self.encode_data(data)
                    if encrypted:
                        length_prefix = struct.pack("!I", len(encrypted))
                        server.send(length_prefix + encrypted)

                        with self.lock:
                            self.total_uploaded += len(data)

                if server in readers:
                    chunk = server.recv(BUFFER_SIZE)
                    if not chunk:
                        break

                    server_buffer += chunk

                    while len(server_buffer) >= 4:
                        packet_length = struct.unpack("!I", server_buffer[:4])[0]

                        if packet_length > MAX_PACKET_SIZE:
                            return

                        if len(server_buffer) >= 4 + packet_length:
                            encrypted_data = server_buffer[4 : 4 + packet_length]
                            server_buffer = server_buffer[4 + packet_length :]

                            decrypted = self.decode_data(encrypted_data)
                            if decrypted:
                                client.send(decrypted)
                                with self.lock:
                                    self.total_downloaded += len(decrypted)
                            else:
                                return
                        else:
                            break

        except:
            pass
        finally:
            try:
                client.close()
            except:
                pass
            try:
                server.close()
            except:
                pass
