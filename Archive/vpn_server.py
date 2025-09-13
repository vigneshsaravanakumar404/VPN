#!/usr/bin/env python3
"""
Universal Proxy Server - Fixed version with better SOCKS5 handling
Supports both HTTP and SOCKS5 protocols for Windows system-wide proxy
"""

import socket
import threading
import struct
import select
from datetime import datetime
import re
import sys
import traceback


class Colors:
    """Colors for terminal output"""

    HEADER = "\033[95m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    END = "\033[0m"
    BOLD = "\033[1m"


class UniversalProxy:
    def __init__(self, http_port=8080, socks_port=1080, debug=False):
        self.http_port = http_port
        self.socks_port = socks_port
        self.connections = 0
        self.debug = debug

    def log_debug(self, msg):
        """Print debug messages if debug mode is on"""
        if self.debug:
            print(f"{Colors.YELLOW}[DEBUG] {msg}{Colors.END}")

    def start(self):
        """Start both HTTP and SOCKS5 proxy servers"""
        print(f"{Colors.GREEN}{Colors.BOLD}")
        print("=" * 60)
        print(f"🚀 UNIVERSAL PROXY SERVER RUNNING")
        print("=" * 60)
        print(f"{Colors.END}")

        # Start HTTP proxy thread
        http_thread = threading.Thread(target=self.start_http_proxy)
        http_thread.daemon = True
        http_thread.start()

        # Start SOCKS5 proxy thread
        socks_thread = threading.Thread(target=self.start_socks5_proxy)
        socks_thread.daemon = True
        socks_thread.start()

        print(f"{Colors.YELLOW}Windows System Proxy Configuration:")
        print(f"  1. Open Windows Settings > Network & Internet > Proxy")
        print(f"  2. Turn OFF 'Automatically detect settings'")
        print(f"  3. Under 'Manual proxy setup', click 'Set up'")
        print(f"  4. Enable 'Use a proxy server'")
        print(f"  5. Address: localhost")
        print(f"  6. Port: {self.http_port}")
        print(f"  7. Check 'Don't use the proxy server for local addresses'")
        print(f"  8. Save{Colors.END}\n")

        print(f"{Colors.BLUE}Firefox SOCKS5 Configuration (optional):")
        print(f"  SOCKS Host: localhost")
        print(f"  Port: {self.socks_port}")
        print(f"  Type: SOCKS v5{Colors.END}\n")

        if self.debug:
            print(f"{Colors.YELLOW}🔍 Debug mode is ON{Colors.END}\n")

        print(f"{Colors.GREEN}Waiting for connections...{Colors.END}\n")

        # Keep main thread alive
        try:
            while True:
                threading.Event().wait(1)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Shutting down proxy...{Colors.END}")
            print(
                f"{Colors.GREEN}Total connections handled: {self.connections}{Colors.END}"
            )

    def start_http_proxy(self):
        """Start HTTP proxy server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind(("0.0.0.0", self.http_port))
            server.listen(50)
            print(
                f"{Colors.GREEN}✓ HTTP Proxy listening on port {self.http_port}{Colors.END}"
            )

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
            print(f"{Colors.RED}HTTP Proxy Error: {e}{Colors.END}")
        finally:
            server.close()

    def start_socks5_proxy(self):
        """Start SOCKS5 proxy server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind(("127.0.0.1", self.socks_port))
            server.listen(50)
            print(
                f"{Colors.GREEN}✓ SOCKS5 Proxy listening on port {self.socks_port}{Colors.END}"
            )

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
            print(f"{Colors.RED}SOCKS5 Proxy Error: {e}{Colors.END}")
        finally:
            server.close()

    def handle_http_client(self, client, addr, conn_num):
        """Handle HTTP proxy client"""
        try:
            client.settimeout(10)

            # Receive the HTTP request
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

            self.log_debug(f"HTTP Request from {addr}:\n{request[:500]}")

            lines = request.split("\n")
            if not lines:
                client.close()
                return

            first_line = lines[0].strip()

            if first_line.startswith("CONNECT"):
                self.handle_https_tunnel(client, request, conn_num)
            else:
                self.handle_http_request(client, request, conn_num)

        except socket.timeout:
            print(f"{Colors.RED}[HTTP #{conn_num}] Request timeout{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[HTTP #{conn_num}] Error: {e}{Colors.END}")
            if self.debug:
                traceback.print_exc()
        finally:
            try:
                client.close()
            except:
                pass

    def handle_https_tunnel(self, client, request, conn_num):
        """Handle HTTPS CONNECT tunneling"""
        first_line = request.split("\n")[0]
        url = first_line.split(" ")[1]

        if ":" in url:
            host, port = url.split(":")
            port = int(port)
        else:
            host = url
            port = 443

        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Colors.BOLD}{Colors.BLUE}[{timestamp}] 🔒 HTTPS Tunnel:{Colors.END}")
        print(f"   {Colors.GREEN}► {host}:{port}{Colors.END}")

        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(10)
            remote.connect((host, port))
            remote.settimeout(None)

            client.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            print(f"   {Colors.GREEN}✓ Tunnel established{Colors.END}")

            self.relay_data(client, remote, host, conn_num)

        except Exception as e:
            print(f"   {Colors.RED}✗ Connection failed: {e}{Colors.END}")
            client.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")

    def handle_http_request(self, client, request, conn_num):
        """Handle regular HTTP requests"""
        first_line = request.split("\n")[0]
        method = first_line.split(" ")[0]
        url = first_line.split(" ")[1]

        host_match = re.search(r"Host: (.+)\r?\n", request)
        if not host_match:
            client.close()
            return

        host = host_match.group(1).strip()
        port = 80

        if ":" in host:
            host, port = host.split(":")
            port = int(port)

        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Colors.BOLD}{Colors.BLUE}[{timestamp}] 🌐 HTTP Request:{Colors.END}")
        print(
            f"   {Colors.GREEN}► {method} {host}:{port}{url[:50]}{'...' if len(url) > 50 else ''}{Colors.END}"
        )

        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(10)
            remote.connect((host, port))
            remote.settimeout(None)

            remote.send(request.encode("utf-8"))

            print(f"   {Colors.GREEN}✓ Request forwarded{Colors.END}")

            self.relay_data(client, remote, host, conn_num)

        except Exception as e:
            print(f"   {Colors.RED}✗ Connection failed: {e}{Colors.END}")
            error_response = b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nProxy Error"
            client.send(error_response)

    def handle_socks5_client(self, client, addr, conn_num):
        """Handle SOCKS5 client with complete error handling"""
        print(
            f"{Colors.GREEN}[SOCKS5 #{conn_num}] New connection from {addr}{Colors.END}"
        )

        try:
            # Step 1: Receive and validate greeting
            greeting = client.recv(2)
            if not greeting or len(greeting) < 2:
                self.log_debug(f"Invalid greeting received: {greeting}")
                client.close()
                return

            version = greeting[0]
            n_methods = greeting[1]

            self.log_debug(f"SOCKS version: {version}, methods: {n_methods}")

            if version != 5:
                print(
                    f"{Colors.RED}[SOCKS5 #{conn_num}] Wrong version: {version}{Colors.END}"
                )
                client.close()
                return

            # Step 2: Receive authentication methods
            methods = client.recv(n_methods)
            if not methods or len(methods) < n_methods:
                self.log_debug(f"Failed to receive all auth methods")
                client.close()
                return

            self.log_debug(f"Auth methods: {[hex(m) for m in methods]}")

            # Step 3: Send no authentication required
            client.send(b"\x05\x00")

            # Step 4: Receive connection request
            request = client.recv(4)
            if not request or len(request) < 4:
                self.log_debug(f"Invalid connection request")
                client.close()
                return

            version, cmd, _, addr_type = struct.unpack("!BBBB", request)

            self.log_debug(f"Connection request - cmd: {cmd}, addr_type: {addr_type}")

            if cmd != 1:  # Only support CONNECT
                print(
                    f"{Colors.RED}[SOCKS5 #{conn_num}] Unsupported command: {cmd}{Colors.END}"
                )
                reply = b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00"
                client.send(reply)
                client.close()
                return

            # Step 5: Parse target address
            target_addr = None
            target_port = None

            try:
                if addr_type == 1:  # IPv4
                    addr_bytes = client.recv(4)
                    if not addr_bytes or len(addr_bytes) != 4:
                        raise ValueError(f"Invalid IPv4 address bytes: {addr_bytes}")
                    target_addr = socket.inet_ntoa(addr_bytes)
                    self.log_debug(f"IPv4 address: {target_addr}")

                elif addr_type == 3:  # Domain name
                    domain_length_bytes = client.recv(1)
                    if not domain_length_bytes:
                        raise ValueError("No domain length received")
                    domain_length = domain_length_bytes[0]
                    self.log_debug(f"Domain name length: {domain_length}")

                    domain_bytes = client.recv(domain_length)
                    if not domain_bytes or len(domain_bytes) != domain_length:
                        raise ValueError(
                            f"Invalid domain bytes: got {len(domain_bytes) if domain_bytes else 0}, expected {domain_length}"
                        )
                    target_addr = domain_bytes.decode("utf-8")
                    self.log_debug(f"Domain name: {target_addr}")

                elif addr_type == 4:  # IPv6
                    addr_bytes = client.recv(16)
                    if not addr_bytes or len(addr_bytes) != 16:
                        raise ValueError(f"Invalid IPv6 address bytes")
                    target_addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
                    self.log_debug(f"IPv6 address: {target_addr}")

                else:
                    raise ValueError(f"Unknown address type: {addr_type}")

                # Step 6: Get port
                port_bytes = client.recv(2)
                if not port_bytes or len(port_bytes) != 2:
                    raise ValueError(f"Invalid port bytes: {port_bytes}")
                target_port = struct.unpack("!H", port_bytes)[0]
                self.log_debug(f"Target port: {target_port}")

            except Exception as e:
                print(
                    f"{Colors.RED}[SOCKS5 #{conn_num}] Error parsing address: {e}{Colors.END}"
                )
                if self.debug:
                    traceback.print_exc()
                # Send general failure
                reply = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"
                client.send(reply)
                client.close()
                return

            # Step 7: Validate we have both address and port
            if not target_addr or target_port is None:
                print(
                    f"{Colors.RED}[SOCKS5 #{conn_num}] Invalid target: addr={target_addr}, port={target_port}{Colors.END}"
                )
                reply = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"
                client.send(reply)
                client.close()
                return

            timestamp = datetime.now().strftime("%H:%M:%S")
            print(
                f"{Colors.BOLD}{Colors.BLUE}[{timestamp}] 🧦 SOCKS5 Request:{Colors.END}"
            )
            print(f"   {Colors.GREEN}► {target_addr}:{target_port}{Colors.END}")

            # Step 8: Connect to target
            try:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.settimeout(10)
                remote.connect((target_addr, target_port))
                remote.settimeout(None)

                # Send success response
                reply = b"\x05\x00\x00\x01"
                reply += socket.inet_aton("0.0.0.0")
                reply += struct.pack("!H", 0)
                client.send(reply)

                print(f"   {Colors.GREEN}✓ Connected via SOCKS5{Colors.END}")

                # Relay data
                self.relay_data(client, remote, target_addr, conn_num)

            except socket.timeout:
                print(f"   {Colors.RED}✗ Connection timeout{Colors.END}")
                reply = b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00"
                client.send(reply)
            except socket.gaierror as e:
                print(f"   {Colors.RED}✗ DNS resolution failed: {e}{Colors.END}")
                reply = b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00"
                client.send(reply)
            except ConnectionRefusedError:
                print(f"   {Colors.RED}✗ Connection refused{Colors.END}")
                reply = b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"
                client.send(reply)
            except Exception as e:
                print(f"   {Colors.RED}✗ Connection failed: {e}{Colors.END}")
                if self.debug:
                    traceback.print_exc()
                reply = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"
                client.send(reply)

        except Exception as e:
            print(f"{Colors.RED}[SOCKS5 #{conn_num}] Unexpected error: {e}{Colors.END}")
            if self.debug:
                traceback.print_exc()
        finally:
            try:
                client.close()
            except:
                pass

    def relay_data(self, client, remote, target, conn_num):
        """Relay data between client and remote server"""
        total_sent = 0
        total_received = 0

        try:
            while True:
                try:
                    readers, _, _ = select.select([client, remote], [], [], 1)

                    if client in readers:
                        data = client.recv(4096)
                        if not data:
                            break
                        remote.send(data)
                        total_sent += len(data)

                    if remote in readers:
                        data = remote.recv(4096)
                        if not data:
                            break
                        client.send(data)
                        total_received += len(data)

                except socket.error as e:
                    if e.errno == 10054:  # Connection reset by peer
                        self.log_debug(f"Connection reset by peer")
                    break
                except Exception as e:
                    self.log_debug(f"Relay error: {e}")
                    break
        finally:
            try:
                client.close()
            except:
                pass
            try:
                remote.close()
            except:
                pass

            if total_sent > 0 or total_received > 0:
                print(
                    f"   {Colors.BLUE}[#{conn_num}] Stats: ↑ {total_sent:,} bytes, ↓ {total_received:,} bytes{Colors.END}"
                )


def main():
    print(f"{Colors.BOLD}{Colors.GREEN}")
    print("╔════════════════════════════════════════════╗")
    print("║   UNIVERSAL PROXY (HTTP + SOCKS5)         ║")
    print("╚════════════════════════════════════════════╝")
    print(f"{Colors.END}")

    # Check for debug flag
    debug = "--debug" in sys.argv or "-d" in sys.argv

    # Check for custom ports
    http_port = 8080
    socks_port = 1080

    for i, arg in enumerate(sys.argv):
        if arg == "--http-port" and i + 1 < len(sys.argv):
            try:
                http_port = int(sys.argv[i + 1])
            except:
                print(f"{Colors.RED}Invalid HTTP port{Colors.END}")
        elif arg == "--socks-port" and i + 1 < len(sys.argv):
            try:
                socks_port = int(sys.argv[i + 1])
            except:
                print(f"{Colors.RED}Invalid SOCKS port{Colors.END}")

    print(f"HTTP Port: {http_port}, SOCKS5 Port: {socks_port}")

    if debug:
        print(
            f"{Colors.YELLOW}🔍 Debug mode enabled - use this to troubleshoot{Colors.END}\n"
        )
    else:
        print(f"Tip: Run with --debug flag to see detailed connection info\n")

    proxy = UniversalProxy(http_port=http_port, socks_port=socks_port, debug=debug)

    try:
        proxy.start()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Proxy stopped{Colors.END}")


if __name__ == "__main__":
    main()
