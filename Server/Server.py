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

load_dotenv()


class VPNServer:
    def __init__(self, listen_port=9999, debug=False):
        self.listen_port = listen_port
        self.connections = 0
        self.debug = debug
        self.encoding_key = os.getenv("ENCODING_KEY", "default_key")
        self.active_clients = {}
        self.total_uploaded = 0
        self.total_downloaded = 0
        self.lock = threading.Lock()

    def encode_data(self, data):
        return data

    def decode_data(self, data):
        return data

    def print_stats(self):
        with self.lock:
            up_mb = self.total_uploaded / (1024 * 1024)
            down_mb = self.total_downloaded / (1024 * 1024)
            print(f"\rUp: {up_mb:.2f} MB | Down: {down_mb:.2f} MB", end="", flush=True)

    def start(self):
        print(f"VPN Server - Port {self.listen_port}")
        print("-" * 40)

        stats_thread = threading.Thread(target=self.stats_printer)
        stats_thread.daemon = True
        stats_thread.start()

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind(("0.0.0.0", self.listen_port))
            server.listen(100)

            while True:
                client, addr = server.accept()
                self.connections += 1

                thread = threading.Thread(
                    target=self.handle_client, args=(client, addr, self.connections)
                )
                thread.daemon = True
                thread.start()

        except KeyboardInterrupt:
            print()
            self.print_stats()
            print()
        except Exception as e:
            pass
        finally:
            server.close()

    def stats_printer(self):
        while True:
            threading.Event().wait(1)
            self.print_stats()

    def cleanup_expired_keys(self):
        while True:
            threading.Event().wait(60)  # Check every minute
            current_time = time.time()
            expired_clients = []

            for addr, key_info in self.client_keys.items():
                if current_time - key_info["last_activity"] > self.key_expiry_seconds:
                    expired_clients.append(addr)

            for addr in expired_clients:
                del self.client_keys[addr]

    def handle_client(self, client, addr, conn_num):
        try:
            header = client.recv(4)
            if not header or len(header) < 4:
                client.close()
                return

            decoded_header = self.decode_data(header)
            request_length = struct.unpack("!I", decoded_header)[0]

            request_data = b""
            while len(request_data) < request_length:
                chunk = client.recv(min(4096, request_length - len(request_data)))
                if not chunk:
                    break
                request_data += chunk

            if len(request_data) < request_length:
                client.close()
                return

            decoded_request = self.decode_data(request_data)
            tunnel_request = json.loads(decoded_request.decode("utf-8"))

            protocol = tunnel_request.get("protocol", "HTTP")
            host = tunnel_request.get("host")
            port = tunnel_request.get("port")

            try:
                target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target.settimeout(10)
                target.connect((host, port))
                target.settimeout(None)

                if protocol == "SOCKS5":
                    client.send(b"\x00")
                    self.relay_data(client, target, host, conn_num)

                elif protocol == "HTTP":
                    if tunnel_request.get("is_connect"):
                        self.relay_data(client, target, host, conn_num)
                    else:
                        request = tunnel_request.get("request", "")
                        if request:
                            target.send(request.encode("utf-8"))
                        self.relay_data(client, target, host, conn_num)

            except:
                if protocol == "SOCKS5":
                    client.send(b"\x01")

        except:
            pass
        finally:
            try:
                client.close()
            except:
                pass

            if addr in self.active_clients:
                del self.active_clients[addr]

    def relay_data(self, client, target, host, conn_num):
        try:
            while True:
                try:
                    readers, _, _ = select.select([client, target], [], [], 1)

                    if client in readers:
                        data = client.recv(4096)
                        if not data:
                            break

                        decoded_data = self.decode_data(data)
                        target.send(decoded_data)
                        with self.lock:
                            self.total_uploaded += len(decoded_data)

                    if target in readers:
                        data = target.recv(4096)
                        if not data:
                            break

                        encoded_data = self.encode_data(data)
                        client.send(encoded_data)
                        with self.lock:
                            self.total_downloaded += len(data)

                except socket.error as e:
                    break
                except Exception as e:
                    break

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
                sys.exit(1)

    server = VPNServer(listen_port=listen_port, debug=debug)

    try:
        server.start()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
