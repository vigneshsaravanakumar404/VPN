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
        self.encoding_key = os.getenv("ENCODING_KEY", "default_key")
        self.total_uploaded = 0
        self.total_downloaded = 0
        self.lock = threading.Lock()

    def encode_data(self, data):
        return data

    def decode_data(self, data):
        return data

    def connect_to_server(self):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((self.server_host, self.server_port))
            return server_socket
        except Exception as e:
            return None

    def print_stats(self):
        with self.lock:
            up_mb = self.total_uploaded / (1024 * 1024)
            down_mb = self.total_downloaded / (1024 * 1024)
            print(f"\rUp: {up_mb:.2f} MB | Down: {down_mb:.2f} MB", end="", flush=True)

    def start(self):
        print(f"VPN Client - {self.server_host}:{self.server_port}")
        print(f"HTTP: localhost:{self.http_port} | SOCKS5: localhost:{self.socks_port}")
        print("-" * 40)

        http_thread = threading.Thread(target=self.start_http_proxy)
        http_thread.daemon = True
        http_thread.start()

        socks_thread = threading.Thread(target=self.start_socks5_proxy)
        socks_thread.daemon = True
        socks_thread.start()

        stats_thread = threading.Thread(target=self.stats_printer)
        stats_thread.daemon = True
        stats_thread.start()

        try:
            while True:
                threading.Event().wait(1)
        except KeyboardInterrupt:
            print()
            self.print_stats()
            print()

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
            pass
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
            pass
        finally:
            server.close()

    def handle_http_client(self, client, addr, conn_num):
        try:
            client.settimeout(10)

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

            server_socket = self.connect_to_server()
            if not server_socket:
                client.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                client.close()
                return

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
                host_match = re.search(r"Host: (.+)\r?\n", request)
                if not host_match:
                    server_socket.close()
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

            tunnel_json = json.dumps(tunnel_request).encode("utf-8")
            tunnel_header = struct.pack("!I", len(tunnel_json))

            encoded_header = self.encode_data(tunnel_header)
            encoded_json = self.encode_data(tunnel_json)

            server_socket.send(encoded_header + encoded_json)

            if tunnel_request["is_connect"]:
                client.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            self.relay_tunnel_data(
                client, server_socket, tunnel_request["host"], conn_num
            )

        except Exception as e:
            pass
        finally:
            try:
                client.close()
            except:
                pass

    def handle_socks5_client(self, client, addr, conn_num):
        try:
            greeting = client.recv(2)
            if not greeting or len(greeting) < 2:
                client.close()
                return

            version = greeting[0]
            n_methods = greeting[1]

            if version != 5:
                client.close()
                return

            methods = client.recv(n_methods)
            if not methods or len(methods) < n_methods:
                client.close()
                return

            client.send(b"\x05\x00")

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

            target_addr = None
            target_port = None

            if addr_type == 1:
                addr_bytes = client.recv(4)
                if addr_bytes and len(addr_bytes) == 4:
                    target_addr = socket.inet_ntoa(addr_bytes)
            elif addr_type == 3:
                domain_length_bytes = client.recv(1)
                if domain_length_bytes:
                    domain_length = domain_length_bytes[0]
                    domain_bytes = client.recv(domain_length)
                    if domain_bytes and len(domain_bytes) == domain_length:
                        target_addr = domain_bytes.decode("utf-8")
            elif addr_type == 4:
                addr_bytes = client.recv(16)
                if addr_bytes and len(addr_bytes) == 16:
                    target_addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)

            port_bytes = client.recv(2)
            if port_bytes and len(port_bytes) == 2:
                target_port = struct.unpack("!H", port_bytes)[0]

            if not target_addr or target_port is None:
                reply = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"
                client.send(reply)
                client.close()
                return

            server_socket = self.connect_to_server()
            if not server_socket:
                reply = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"
                client.send(reply)
                client.close()
                return

            tunnel_request = {
                "protocol": "SOCKS5",
                "host": target_addr,
                "port": target_port,
                "addr_type": addr_type,
            }

            tunnel_json = json.dumps(tunnel_request).encode("utf-8")
            tunnel_header = struct.pack("!I", len(tunnel_json))

            encoded_header = self.encode_data(tunnel_header)
            encoded_json = self.encode_data(tunnel_json)

            server_socket.send(encoded_header + encoded_json)

            response = server_socket.recv(1)
            if response == b"\x00":
                reply = b"\x05\x00\x00\x01"
                reply += socket.inet_aton("0.0.0.0")
                reply += struct.pack("!H", 0)
                client.send(reply)

                self.relay_tunnel_data(client, server_socket, target_addr, conn_num)
            else:
                reply = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"
                client.send(reply)
                server_socket.close()

        except Exception as e:
            pass
        finally:
            try:
                client.close()
            except:
                pass

    def relay_tunnel_data(self, client, server, target, conn_num):
        try:
            while True:
                try:
                    readers, _, _ = select.select([client, server], [], [], 1)

                    if client in readers:
                        data = client.recv(4096)
                        if not data:
                            break
                        encoded_data = self.encode_data(data)
                        server.send(encoded_data)
                        with self.lock:
                            self.total_uploaded += len(data)

                    if server in readers:
                        data = server.recv(4096)
                        if not data:
                            break
                        decoded_data = self.decode_data(data)
                        client.send(decoded_data)
                        with self.lock:
                            self.total_downloaded += len(decoded_data)

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
                server.close()
            except:
                pass


def main():
    server_host = os.getenv("VPN_SERVER_HOST", "your-ec2-instance.amazonaws.com")
    server_port = int(os.getenv("VPN_SERVER_PORT", "9999"))

    debug = "--debug" in sys.argv or "-d" in sys.argv

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
