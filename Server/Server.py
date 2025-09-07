#!/usr/bin/env python3
"""
VPN Server - Minimal output with auto-generated encryption keys
"""

import socket
import threading
import struct
import select
import json
import os
import sys
import time
import secrets
from datetime import datetime


class VPNServer:
    def __init__(self, listen_port=8888):
        self.listen_port = listen_port
        self.active_connections = 0
        self.total_connections = 0
        self.total_uploaded = 0
        self.total_downloaded = 0
        self.client_keys = {}  # Store encryption keys per client
        self.lock = threading.Lock()

    def generate_key(self):
        """Generate a random 256-byte encryption key"""
        return secrets.token_bytes(256)

    def encode_data(self, data, key):
        """XOR encode data with key"""
        encoded = bytearray()
        for i, byte in enumerate(data):
            encoded.append(byte ^ key[i % len(key)])
        return bytes(encoded)

    def decode_data(self, data, key):
        """XOR decode data with key"""
        return self.encode_data(data, key)  # XOR is symmetric

    def update_display(self):
        """Update statistics display"""
        with self.lock:
            up_gb = self.total_uploaded / (1024 * 1024 * 1024)
            down_gb = self.total_downloaded / (1024 * 1024 * 1024)
            up_mb = (self.total_uploaded / (1024 * 1024)) % 1024
            down_mb = (self.total_downloaded / (1024 * 1024)) % 1024

            # Clear line and print stats
            print(
                f"\rConnections: {self.active_connections} active, {self.total_connections} total | "
                f"Up: {up_gb:.1f}GB {up_mb:.0f}MB | Down: {down_gb:.1f}GB {down_mb:.0f}MB",
                end="",
                flush=True,
            )

    def start(self):
        """Start VPN server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind(("0.0.0.0", self.listen_port))
            server.listen(100)
            print(f"VPN Server running on port {self.listen_port}")

            # Stats update thread
            stats_thread = threading.Thread(target=self.stats_updater)
            stats_thread.daemon = True
            stats_thread.start()

            while True:
                client, addr = server.accept()

                with self.lock:
                    self.total_connections += 1
                    self.active_connections += 1

                # Generate unique key for this client
                client_key = self.generate_key()
                client_id = f"{addr[0]}:{addr[1]}_{self.total_connections}"
                self.client_keys[client_id] = client_key

                thread = threading.Thread(
                    target=self.handle_client, args=(client, client_id, client_key)
                )
                thread.daemon = True
                thread.start()

        except KeyboardInterrupt:
            print("\nShutdown")
        except Exception as e:
            print(f"\nServer error: {e}")
        finally:
            server.close()

    def stats_updater(self):
        """Update stats display periodically"""
        while True:
            self.update_display()
            time.sleep(1)

    def handle_client(self, client, client_id, client_key):
        """Handle VPN client connection"""
        target_socket = None

        try:
            # Send encryption key to client
            client.send(struct.pack("!I", len(client_key)))
            client.send(client_key)

            # Receive request header
            header_data = client.recv(4)
            if not header_data or len(header_data) < 4:
                return

            # Decode header
            decoded_header = self.decode_data(header_data, client_key)
            request_length = struct.unpack("!I", decoded_header)[0]

            # Receive request
            request_data = b""
            while len(request_data) < request_length:
                chunk = client.recv(min(4096, request_length - len(request_data)))
                if not chunk:
                    break
                request_data += chunk

            if len(request_data) < request_length:
                return

            # Decode and parse request
            decoded_request = self.decode_data(request_data, client_key)
            request = json.loads(decoded_request.decode("utf-8"))

            target_host = request.get("host")
            target_port = request.get("port")
            request_type = request.get("type")

            # Connect to target
            try:
                target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_socket.settimeout(10)
                target_socket.connect((target_host, target_port))
                target_socket.settimeout(None)

                # Send success
                client.send(b"\x00")

                # Handle initial HTTP data if present
                if request_type == "HTTP":
                    length_bytes = client.recv(4)
                    if length_bytes and len(length_bytes) == 4:
                        data_length = struct.unpack("!I", length_bytes)[0]

                        encoded_data = b""
                        while len(encoded_data) < data_length:
                            chunk = client.recv(
                                min(4096, data_length - len(encoded_data))
                            )
                            if not chunk:
                                break
                            encoded_data += chunk

                        if len(encoded_data) == data_length:
                            initial_data = self.decode_data(encoded_data, client_key)
                            target_socket.send(initial_data)

                # Relay data
                self.relay_data(client, target_socket, client_key)

            except:
                client.send(b"\x01")  # Send failure

        except:
            pass
        finally:
            # Cleanup
            with self.lock:
                self.active_connections -= 1

            if client_id in self.client_keys:
                del self.client_keys[client_id]

            try:
                if target_socket:
                    target_socket.close()
            except:
                pass
            try:
                client.close()
            except:
                pass

    def relay_data(self, client_socket, target_socket, client_key):
        """Relay data between VPN client and target"""
        try:
            while True:
                try:
                    readers, _, _ = select.select(
                        [client_socket, target_socket], [], [], 1
                    )

                    # Data from VPN client to target
                    if client_socket in readers:
                        # Read length prefix
                        length_bytes = client_socket.recv(4)
                        if not length_bytes or len(length_bytes) < 4:
                            break

                        length = struct.unpack("!I", length_bytes)[0]

                        # Read encoded data
                        encoded_data = b""
                        while len(encoded_data) < length:
                            chunk = client_socket.recv(
                                min(4096, length - len(encoded_data))
                            )
                            if not chunk:
                                break
                            encoded_data += chunk

                        if len(encoded_data) < length:
                            break

                        # Decode and send to target
                        data = self.decode_data(encoded_data, client_key)
                        target_socket.send(data)

                        with self.lock:
                            self.total_uploaded += len(data)

                    # Data from target to VPN client
                    if target_socket in readers:
                        data = target_socket.recv(4096)
                        if not data:
                            break

                        # Encode data
                        encoded_data = self.encode_data(data, client_key)

                        # Send with length prefix
                        client_socket.send(struct.pack("!I", len(encoded_data)))
                        client_socket.send(encoded_data)

                        with self.lock:
                            self.total_downloaded += len(data)

                except socket.error:
                    break
                except:
                    break

        except:
            pass


def main():
    # Get port from args
    port = 8888

    for i, arg in enumerate(sys.argv):
        if arg == "--port" and i + 1 < len(sys.argv):
            try:
                port = int(sys.argv[i + 1])
            except:
                pass

    server = VPNServer(listen_port=port)

    try:
        server.start()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
