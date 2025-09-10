#!/usr/bin/env python3

import socket
import threading
import struct
import select
import json
import os
from datetime import datetime
import sys
import traceback
from dotenv import load_dotenv
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

load_dotenv()


class VPNServer:
    def __init__(self, listen_port=9999, debug=False):
        self.listen_port = listen_port
        self.connections = 0
        self.debug = debug
        self.active_clients = {}
        self.total_uploaded = 0
        self.total_downloaded = 0
        self.lock = threading.Lock()

        # Initialize encryption
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

    def print_stats(self):
        with self.lock:
            up_mb = self.total_uploaded / (1024 * 1024)
            down_mb = self.total_downloaded / (1024 * 1024)
            active_sessions = len(self.active_clients)
            print(
                f"\rSessions: {active_sessions} | Up: {up_mb:.2f} MB | Down: {down_mb:.2f} MB",
                end="",
                flush=True,
            )

    def start(self):
        print("=" * 50)
        print(f"VPN Server - Port {self.listen_port}")
        print(f"Encryption: AES-256-GCM")
        print("=" * 50)

        password = os.getenv("VPN_PASSWORD", "change_this_password_immediately")
        if password == "change_this_password_immediately":
            print("⚠️  WARNING: Using default password!")
            print("   Set: $env:VPN_PASSWORD = 'YourPassword'")
        else:
            print(f"✓ Password set ({len(password)} chars)")
        print()

        stats_thread = threading.Thread(target=self.stats_printer)
        stats_thread.daemon = True
        stats_thread.start()

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind(("0.0.0.0", self.listen_port))
            server.listen(100)
            print(f"Listening on 0.0.0.0:{self.listen_port}")
            print()

            while True:
                client, addr = server.accept()
                self.connections += 1
                thread = threading.Thread(
                    target=self.handle_client, args=(client, addr, self.connections)
                )
                thread.daemon = True
                thread.start()

        except KeyboardInterrupt:
            print("\n\nShutting down...")
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            server.close()

    def stats_printer(self):
        while True:
            threading.Event().wait(1)
            self.print_stats()

    def handle_client(self, client, addr, conn_num):
        session_id = str(uuid.uuid4())[:8]

        with self.lock:
            self.active_clients[session_id] = {
                "address": addr,
                "connected_at": datetime.now(),
                "conn_num": conn_num,
            }
            if self.debug:
                print(
                    f"\n[Session {session_id}] New connection from {addr[0]}:{addr[1]}"
                )

        try:
            # Receive initial handshake packet
            # Format: [4-byte length][encrypted JSON request]
            length_data = client.recv(4)
            if not length_data or len(length_data) < 4:
                return

            packet_length = struct.unpack("!I", length_data)[0]

            if packet_length > 1024 * 1024:  # Max 1MB
                if self.debug:
                    print(f"[Session {session_id}] Packet too large: {packet_length}")
                return

            # Receive encrypted packet
            encrypted_packet = b""
            while len(encrypted_packet) < packet_length:
                chunk = client.recv(min(4096, packet_length - len(encrypted_packet)))
                if not chunk:
                    break
                encrypted_packet += chunk

            if len(encrypted_packet) < packet_length:
                return

            # Decrypt packet
            decrypted_packet = self.decode_data(encrypted_packet)
            if not decrypted_packet:
                if self.debug:
                    print(
                        f"[Session {session_id}] Decryption failed - password mismatch"
                    )
                return

            # Parse JSON request
            tunnel_request = json.loads(decrypted_packet.decode("utf-8"))

            protocol = tunnel_request.get("protocol", "HTTP")
            host = tunnel_request.get("host")
            port = tunnel_request.get("port")

            if self.debug:
                print(f"[Session {session_id}] {protocol} -> {host}:{port}")

            # Connect to target
            target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target.settimeout(10)

            try:
                target.connect((host, port))
                target.settimeout(None)

                if protocol == "SOCKS5":
                    client.send(b"\x00")  # Success
                elif protocol == "HTTP" and tunnel_request.get("is_connect"):
                    # Don't send anything for HTTPS CONNECT, client handles it
                    pass
                elif protocol == "HTTP":
                    # Send initial HTTP request if provided
                    request = tunnel_request.get("request", "")
                    if request:
                        target.send(request.encode("utf-8"))

                # Start relaying data
                self.relay_data(client, target, session_id)

            except Exception as e:
                if self.debug:
                    print(f"[Session {session_id}] Target connection failed: {e}")
                if protocol == "SOCKS5":
                    client.send(b"\x01")  # Failure

        except Exception as e:
            if self.debug:
                print(f"[Session {session_id}] Error: {e}")
        finally:
            client.close()

            with self.lock:
                if session_id in self.active_clients:
                    if self.debug:
                        print(f"[Session {session_id}] Closed")
                    del self.active_clients[session_id]

    def relay_data(self, client, target, session_id):
        """Relay data between client and target with proper framing"""

        # Buffers for partial packets
        client_buffer = b""

        try:
            while True:
                readers, _, _ = select.select([client, target], [], [], 1)

                # Data from client (encrypted)
                if client in readers:
                    chunk = client.recv(4096)
                    if not chunk:
                        break

                    client_buffer += chunk

                    # Process complete packets from buffer
                    while len(client_buffer) >= 4:
                        # Check if we have the length header
                        packet_length = struct.unpack("!I", client_buffer[:4])[0]

                        # Check for invalid packet length
                        if packet_length > 1024 * 1024:
                            if self.debug:
                                print(
                                    f"[Session {session_id}] Invalid packet length in relay: {packet_length}"
                                )
                            return

                        # Check if we have the complete packet
                        if len(client_buffer) >= 4 + packet_length:
                            # Extract the complete packet
                            encrypted_data = client_buffer[4 : 4 + packet_length]
                            client_buffer = client_buffer[4 + packet_length :]

                            # Decrypt and forward
                            decrypted = self.decode_data(encrypted_data)
                            if decrypted:
                                target.send(decrypted)
                                with self.lock:
                                    self.total_uploaded += len(decrypted)
                            else:
                                if self.debug:
                                    print(
                                        f"[Session {session_id}] Relay decryption failed"
                                    )
                                return
                        else:
                            # Need more data
                            break

                # Data from target (plaintext)
                if target in readers:
                    data = target.recv(4096)
                    if not data:
                        break

                    # Encrypt data
                    encrypted = self.encode_data(data)
                    if encrypted:
                        # Send with length prefix
                        length_prefix = struct.pack("!I", len(encrypted))
                        client.send(length_prefix + encrypted)

                        with self.lock:
                            self.total_downloaded += len(data)
                    else:
                        if self.debug:
                            print(f"[Session {session_id}] Relay encryption failed")
                        return

        except Exception as e:
            if self.debug:
                print(f"[Session {session_id}] Relay error: {e}")
        finally:
            try:
                client.close()
            except:
                pass
            try:
                target.close()
            except:
                pass


def main():
    debug = "--debug" in sys.argv or "-d" in sys.argv

    listen_port = int(os.getenv("VPN_SERVER_PORT", "9999"))

    for i, arg in enumerate(sys.argv):
        if arg == "--port" and i + 1 < len(sys.argv):
            try:
                listen_port = int(sys.argv[i + 1])
            except:
                print("Invalid port number")
                sys.exit(1)

    server = VPNServer(listen_port=listen_port, debug=debug)

    try:
        server.start()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()