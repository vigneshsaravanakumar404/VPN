#!/usr/bin/env python3
"""
Complete GUI VPN Client with Working Proxy Implementation
This version includes the full proxy server code
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import socket
import struct
import select
import json
import os
import sys
import time
import winreg
import re
from datetime import datetime
from pathlib import Path
from PIL import Image, ImageDraw
import pystray
from pystray import MenuItem as item
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configuration
DEFAULT_SERVER = "localhost"
DEFAULT_PORT = 9999
DEFAULT_HTTP_PORT = 8080
DEFAULT_SOCKS_PORT = 1080
DEFAULT_PASSWORD = "change_this_password_immediately"

# Dark theme colors
COLORS = {
    "bg": "#1e1e1e",
    "fg": "#ffffff",
    "accent": "#007acc",
    "success": "#4ec9b0",
    "error": "#f44747",
    "warning": "#ffcc00",
    "card_bg": "#2d2d30",
    "border": "#3e3e42",
    "text_secondary": "#969696",
    "button_bg": "#0e639c",
    "button_hover": "#1177bb",
    "disabled": "#5a5a5a",
}


class VPNClient:
    """Complete VPN client with full proxy implementation"""

    def __init__(
        self, server_host, server_port, http_port=8080, socks_port=1080, debug=False
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.http_port = http_port
        self.socks_port = socks_port
        self.debug = debug
        self.total_uploaded = 0
        self.total_downloaded = 0
        self.active = False
        self.stop_event = threading.Event()
        self.lock = threading.Lock()

        # Initialize encryption
        password = os.getenv("VPN_PASSWORD", DEFAULT_PASSWORD)
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
            print(f"[DEBUG] VPN Client initialized")
            print(f"[DEBUG] Server: {server_host}:{server_port}")
            print(f"[DEBUG] HTTP Proxy: localhost:{http_port}")

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
        except Exception as e:
            if self.debug:
                print(f"[ERROR] Decryption failed: {e}")
            return None

    def connect_to_server(self):
        """Connect to VPN server"""
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

    def test_connection(self):
        """Test connection to VPN server"""
        sock = self.connect_to_server()
        if sock:
            sock.close()
            return True
        return False

    def start(self):
        """Start VPN proxy servers"""
        if self.debug:
            print("[DEBUG] Starting VPN client...")

        self.stop_event.clear()
        self.active = True

        # Start HTTP proxy thread
        http_thread = threading.Thread(target=self.start_http_proxy, daemon=True)
        http_thread.start()

        # Start SOCKS5 proxy thread
        socks_thread = threading.Thread(target=self.start_socks5_proxy, daemon=True)
        socks_thread.start()

        if self.debug:
            print("[DEBUG] Proxy servers started")

    def stop(self):
        """Stop VPN proxy servers"""
        if self.debug:
            print("[DEBUG] Stopping VPN client...")

        self.active = False
        self.stop_event.set()

    def start_http_proxy(self):
        """Run HTTP proxy server"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.settimeout(1)
            server.bind(("0.0.0.0", self.http_port))
            server.listen(50)

            if self.debug:
                print(f"[DEBUG] HTTP proxy listening on 0.0.0.0:{self.http_port}")

            while not self.stop_event.is_set():
                try:
                    client, addr = server.accept()
                    if not self.stop_event.is_set():
                        thread = threading.Thread(
                            target=self.handle_http_client,
                            args=(client, addr),
                            daemon=True,
                        )
                        thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.debug:
                        print(f"[ERROR] HTTP proxy: {e}")
                    break

            server.close()
        except Exception as e:
            if self.debug:
                print(f"[ERROR] Failed to start HTTP proxy: {e}")

    def start_socks5_proxy(self):
        """Run SOCKS5 proxy server"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.settimeout(1)
            server.bind(("127.0.0.1", self.socks_port))
            server.listen(50)

            if self.debug:
                print(f"[DEBUG] SOCKS5 proxy listening on 127.0.0.1:{self.socks_port}")

            while not self.stop_event.is_set():
                try:
                    client, addr = server.accept()
                    if not self.stop_event.is_set():
                        thread = threading.Thread(
                            target=self.handle_socks5_client,
                            args=(client, addr),
                            daemon=True,
                        )
                        thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.debug:
                        print(f"[ERROR] SOCKS5 proxy: {e}")
                    break

            server.close()
        except Exception as e:
            if self.debug:
                print(f"[ERROR] Failed to start SOCKS5 proxy: {e}")

    def send_handshake(self, server_socket, tunnel_request):
        """Send initial handshake packet to server"""
        tunnel_json = json.dumps(tunnel_request).encode("utf-8")
        encrypted_packet = self.encode_data(tunnel_json)

        if not encrypted_packet:
            return False

        packet_length = struct.pack("!I", len(encrypted_packet))
        server_socket.send(packet_length + encrypted_packet)
        return True

    def handle_http_client(self, client, addr):
        """Handle HTTP client connection"""
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
                print(f"[HTTP] {tunnel_request['method']} {host}:{port}")

            # Connect to VPN server
            server_socket = self.connect_to_server()
            if not server_socket:
                client.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                client.close()
                return

            # Send handshake
            if not self.send_handshake(server_socket, tunnel_request):
                server_socket.close()
                client.close()
                return

            # Send 200 OK for CONNECT method
            if tunnel_request["is_connect"]:
                client.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            # Relay data
            self.relay_tunnel_data(client, server_socket)

        except Exception as e:
            if self.debug:
                print(f"[ERROR] HTTP handler: {e}")
        finally:
            try:
                client.close()
            except:
                pass

    def handle_socks5_client(self, client, addr):
        """Handle SOCKS5 client connection"""
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
                print(f"[SOCKS5] Connect to {target_addr}:{target_port}")

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
                self.relay_tunnel_data(client, server_socket)
            else:
                # Failed
                client.send(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                server_socket.close()

        except Exception as e:
            if self.debug:
                print(f"[ERROR] SOCKS5 handler: {e}")
        finally:
            try:
                client.close()
            except:
                pass

    def relay_tunnel_data(self, client, server):
        """Relay data between browser and VPN server with proper framing"""
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
                        length_prefix = struct.pack("!I", len(encrypted))
                        server.send(length_prefix + encrypted)

                        with self.lock:
                            self.total_uploaded += len(data)

                # Data from VPN server (encrypted)
                if server in readers:
                    chunk = server.recv(4096)
                    if not chunk:
                        break

                    server_buffer += chunk

                    # Process complete packets from buffer
                    while len(server_buffer) >= 4:
                        packet_length = struct.unpack("!I", server_buffer[:4])[0]

                        if packet_length > 1024 * 1024:
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

        except Exception as e:
            if self.debug:
                print(f"[ERROR] Relay error: {e}")
        finally:
            try:
                client.close()
            except:
                pass
            try:
                server.close()
            except:
                pass


class WindowsProxyManager:
    """Manage Windows system proxy settings"""

    INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    @staticmethod
    def enable(server, port):
        """Enable Windows system proxy"""
        try:
            proxy_server = f"{server}:{port}"
            proxy_override = "localhost;127.0.0.1;*.local;<local>"

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                WindowsProxyManager.INTERNET_SETTINGS,
                0,
                winreg.KEY_WRITE,
            )

            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_server)
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, proxy_override)
            winreg.SetValueEx(key, "AutoDetect", 0, winreg.REG_DWORD, 0)

            winreg.CloseKey(key)
            WindowsProxyManager._refresh()
            return True
        except Exception as e:
            print(f"[ERROR] Failed to enable Windows proxy: {e}")
            return False

    @staticmethod
    def disable():
        """Disable Windows system proxy"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                WindowsProxyManager.INTERNET_SETTINGS,
                0,
                winreg.KEY_WRITE,
            )

            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            WindowsProxyManager._refresh()
            return True
        except Exception as e:
            print(f"[ERROR] Failed to disable Windows proxy: {e}")
            return False

    @staticmethod
    def _refresh():
        """Refresh Internet settings"""
        import ctypes

        try:
            internet = ctypes.windll.Wininet
            internet.InternetSetOptionW(0, 39, 0, 0)
            internet.InternetSetOptionW(0, 37, 0, 0)
        except:
            pass


class VPNGui(tk.Tk):
    """Modern GUI for VPN Client"""

    def __init__(self):
        super().__init__()

        self.vpn_client = None
        self.is_connected = False
        self.stats_update_thread = None
        self.tray_icon = None

        # Configure window
        self.title("VPN Client")
        self.geometry("400x500")
        self.configure(bg=COLORS["bg"])
        self.resizable(False, False)

        # Protocol for window close
        self.protocol("WM_DELETE_WINDOW", self.minimize_to_tray)

        # Create GUI
        self.setup_styles()
        self.create_widgets()

        # Start system tray
        self.setup_system_tray()

        # Load settings
        self.load_settings()

        # Center window
        self.center_window()

    def setup_styles(self):
        """Configure ttk styles for dark theme"""
        self.style = ttk.Style()
        self.style.theme_use("clam")

    def create_widgets(self):
        """Create GUI widgets"""

        # Main container
        main_frame = tk.Frame(self, bg=COLORS["bg"])
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        title_label = tk.Label(
            main_frame,
            text="VPN CLIENT",
            bg=COLORS["bg"],
            fg=COLORS["fg"],
            font=("Segoe UI", 20, "bold"),
        )
        title_label.pack(pady=(0, 20))

        # Status Card
        status_frame = tk.Frame(
            main_frame,
            bg=COLORS["card_bg"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        status_frame.pack(fill="x", pady=(0, 15))

        status_inner = tk.Frame(status_frame, bg=COLORS["card_bg"])
        status_inner.pack(padx=15, pady=15)

        # Status indicator
        self.status_dot = tk.Canvas(
            status_inner,
            width=12,
            height=12,
            bg=COLORS["card_bg"],
            highlightthickness=0,
        )
        self.status_dot.pack(side="left", padx=(0, 10))
        self.update_status_dot(False)

        self.status_label = tk.Label(
            status_inner,
            text="Disconnected",
            bg=COLORS["card_bg"],
            fg=COLORS["fg"],
            font=("Segoe UI", 12),
        )
        self.status_label.pack(side="left")

        # Connection Settings Card
        settings_frame = tk.Frame(
            main_frame,
            bg=COLORS["card_bg"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        settings_frame.pack(fill="x", pady=(0, 15))

        settings_inner = tk.Frame(settings_frame, bg=COLORS["card_bg"])
        settings_inner.pack(padx=15, pady=15)

        # Server input
        tk.Label(
            settings_inner,
            text="Server",
            bg=COLORS["card_bg"],
            fg=COLORS["text_secondary"],
            font=("Segoe UI", 9),
        ).grid(row=0, column=0, sticky="w", pady=2)

        self.server_entry = tk.Entry(
            settings_inner,
            bg=COLORS["bg"],
            fg=COLORS["fg"],
            insertbackground=COLORS["fg"],
            relief="flat",
            font=("Segoe UI", 10),
        )
        self.server_entry.grid(row=0, column=1, padx=(10, 0), sticky="ew")
        self.server_entry.insert(0, DEFAULT_SERVER)

        # Port input
        tk.Label(
            settings_inner,
            text="Port",
            bg=COLORS["card_bg"],
            fg=COLORS["text_secondary"],
            font=("Segoe UI", 9),
        ).grid(row=1, column=0, sticky="w", pady=2)

        self.port_entry = tk.Entry(
            settings_inner,
            bg=COLORS["bg"],
            fg=COLORS["fg"],
            insertbackground=COLORS["fg"],
            relief="flat",
            font=("Segoe UI", 10),
        )
        self.port_entry.grid(row=1, column=1, padx=(10, 0), sticky="ew")
        self.port_entry.insert(0, str(DEFAULT_PORT))

        settings_inner.columnconfigure(1, weight=1)

        # Statistics Card
        stats_frame = tk.Frame(
            main_frame,
            bg=COLORS["card_bg"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        stats_frame.pack(fill="x", pady=(0, 15))

        stats_inner = tk.Frame(stats_frame, bg=COLORS["card_bg"])
        stats_inner.pack(padx=15, pady=15)

        # Upload stats
        tk.Label(
            stats_inner,
            text="Upload",
            bg=COLORS["card_bg"],
            fg=COLORS["text_secondary"],
            font=("Segoe UI", 9),
        ).grid(row=0, column=0, sticky="w")

        self.upload_label = tk.Label(
            stats_inner,
            text="0.00 MB",
            bg=COLORS["card_bg"],
            fg=COLORS["success"],
            font=("Segoe UI", 11, "bold"),
        )
        self.upload_label.grid(row=0, column=1, padx=(20, 0), sticky="e")

        # Download stats
        tk.Label(
            stats_inner,
            text="Download",
            bg=COLORS["card_bg"],
            fg=COLORS["text_secondary"],
            font=("Segoe UI", 9),
        ).grid(row=1, column=0, sticky="w", pady=(5, 0))

        self.download_label = tk.Label(
            stats_inner,
            text="0.00 MB",
            bg=COLORS["card_bg"],
            fg=COLORS["accent"],
            font=("Segoe UI", 11, "bold"),
        )
        self.download_label.grid(row=1, column=1, padx=(20, 0), sticky="e", pady=(5, 0))

        stats_inner.columnconfigure(1, weight=1)

        # Connect Button
        self.connect_btn = tk.Button(
            main_frame,
            text="CONNECT",
            bg=COLORS["button_bg"],
            fg=COLORS["fg"],
            font=("Segoe UI", 11, "bold"),
            relief="flat",
            cursor="hand2",
            activebackground=COLORS["button_hover"],
            activeforeground=COLORS["fg"],
            command=self.toggle_connection,
            pady=10,
        )
        self.connect_btn.pack(fill="x", pady=(0, 10))

        # Windows Proxy Checkbox
        self.proxy_var = tk.BooleanVar(value=True)
        self.proxy_check = tk.Checkbutton(
            main_frame,
            text="Configure Windows Proxy",
            bg=COLORS["bg"],
            fg=COLORS["text_secondary"],
            selectcolor=COLORS["bg"],
            activebackground=COLORS["bg"],
            activeforeground=COLORS["fg"],
            font=("Segoe UI", 9),
            variable=self.proxy_var,
        )
        self.proxy_check.pack()

        # Debug checkbox
        self.debug_var = tk.BooleanVar(value=True)
        self.debug_check = tk.Checkbutton(
            main_frame,
            text="Debug mode",
            bg=COLORS["bg"],
            fg=COLORS["text_secondary"],
            selectcolor=COLORS["bg"],
            activebackground=COLORS["bg"],
            activeforeground=COLORS["fg"],
            font=("Segoe UI", 9),
            variable=self.debug_var,
        )
        self.debug_check.pack()

        # Footer
        footer = tk.Label(
            main_frame,
            text="Click × to minimize to tray",
            bg=COLORS["bg"],
            fg=COLORS["text_secondary"],
            font=("Segoe UI", 8),
        )
        footer.pack(side="bottom", pady=(10, 0))

    def update_status_dot(self, connected):
        """Update status indicator dot"""
        self.status_dot.delete("all")
        color = COLORS["success"] if connected else COLORS["text_secondary"]
        self.status_dot.create_oval(2, 2, 10, 10, fill=color, outline=color)

    def toggle_connection(self):
        """Toggle VPN connection"""
        if not self.is_connected:
            self.connect_vpn()
        else:
            self.disconnect_vpn()

    def connect_vpn(self):
        """Connect to VPN"""
        server = self.server_entry.get()
        try:
            port = int(self.port_entry.get())
        except:
            messagebox.showerror("Error", "Invalid port number")
            return

        # Disable inputs
        self.server_entry.config(state="disabled")
        self.port_entry.config(state="disabled")
        self.connect_btn.config(text="Connecting...", state="disabled")

        # Connect in thread
        thread = threading.Thread(
            target=self._connect_vpn_thread, args=(server, port), daemon=True
        )
        thread.start()

    def _connect_vpn_thread(self, server, port):
        """Connect to VPN in thread"""
        try:
            # Create VPN client
            debug = self.debug_var.get()
            self.vpn_client = VPNClient(
                server, port, DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT, debug=debug
            )

            # Test connection
            if not self.vpn_client.test_connection():
                self.after(
                    0,
                    self._connection_failed,
                    f"Cannot connect to VPN server at {server}:{port}",
                )
                return

            # Start VPN proxy servers
            self.vpn_client.start()

            # Configure Windows proxy if enabled
            if self.proxy_var.get():
                WindowsProxyManager.enable("localhost", DEFAULT_HTTP_PORT)

            # Update UI
            self.after(0, self._connection_success)

            # Start stats updater
            self.stats_update_thread = threading.Thread(
                target=self._update_stats_loop, daemon=True
            )
            self.stats_update_thread.start()

        except Exception as e:
            self.after(0, self._connection_failed, str(e))

    def _connection_success(self):
        """Handle successful connection"""
        self.is_connected = True
        self.connect_btn.config(text="DISCONNECT", state="normal", bg=COLORS["error"])
        self.status_label.config(text="Connected")
        self.update_status_dot(True)

        if self.tray_icon:
            self.tray_icon.title = "VPN Client - Connected"

    def _connection_failed(self, error):
        """Handle connection failure"""
        self.server_entry.config(state="normal")
        self.port_entry.config(state="normal")
        self.connect_btn.config(text="CONNECT", state="normal")
        messagebox.showerror("Connection Failed", error)

    def disconnect_vpn(self):
        """Disconnect from VPN"""
        if self.vpn_client:
            self.vpn_client.stop()

        # Disable Windows proxy
        if self.proxy_var.get():
            WindowsProxyManager.disable()

        self.is_connected = False
        self.vpn_client = None

        # Update UI
        self.server_entry.config(state="normal")
        self.port_entry.config(state="normal")
        self.connect_btn.config(text="CONNECT", bg=COLORS["button_bg"])
        self.status_label.config(text="Disconnected")
        self.update_status_dot(False)

        if self.tray_icon:
            self.tray_icon.title = "VPN Client - Disconnected"

    def _update_stats_loop(self):
        """Update statistics in loop"""
        while self.is_connected and self.vpn_client:
            if self.vpn_client:
                upload_mb = self.vpn_client.total_uploaded / (1024 * 1024)
                download_mb = self.vpn_client.total_downloaded / (1024 * 1024)

                self.after(0, self.upload_label.config, {"text": f"{upload_mb:.2f} MB"})
                self.after(
                    0, self.download_label.config, {"text": f"{download_mb:.2f} MB"}
                )

            time.sleep(1)

    def setup_system_tray(self):
        """Setup system tray icon"""
        # Create icon image
        image = Image.new("RGB", (64, 64), color="black")
        draw = ImageDraw.Draw(image)
        draw.ellipse([16, 16, 48, 48], fill=COLORS["accent"])

        # Create menu
        menu = pystray.Menu(
            item("Show", self.show_window, default=True),
            item(
                "Connect",
                lambda: self.after(0, self.connect_vpn),
                visible=lambda item: not self.is_connected,
            ),
            item(
                "Disconnect",
                lambda: self.after(0, self.disconnect_vpn),
                visible=lambda item: self.is_connected,
            ),
            pystray.Menu.SEPARATOR,
            item("Exit", self.quit_app),
        )

        # Create tray icon
        self.tray_icon = pystray.Icon(
            "VPN Client", image, "VPN Client - Disconnected", menu
        )

        # Start in thread
        thread = threading.Thread(target=self.tray_icon.run, daemon=True)
        thread.start()

    def minimize_to_tray(self):
        """Minimize window to system tray"""
        self.withdraw()

    def show_window(self):
        """Show window from tray"""
        self.deiconify()
        self.lift()
        self.focus_force()

    def quit_app(self):
        """Quit application"""
        if self.is_connected:
            self.disconnect_vpn()

        if self.tray_icon:
            self.tray_icon.stop()

        self.quit()
        sys.exit(0)

    def center_window(self):
        """Center window on screen"""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def load_settings(self):
        """Load saved settings"""
        try:
            settings_file = Path.home() / ".vpn_client_settings.json"
            if settings_file.exists():
                import json

                with open(settings_file) as f:
                    settings = json.load(f)
                    self.server_entry.delete(0, "end")
                    self.server_entry.insert(0, settings.get("server", DEFAULT_SERVER))
                    self.port_entry.delete(0, "end")
                    self.port_entry.insert(0, settings.get("port", DEFAULT_PORT))
                    self.proxy_var.set(settings.get("use_proxy", True))
        except:
            pass

    def save_settings(self):
        """Save current settings"""
        try:
            settings_file = Path.home() / ".vpn_client_settings.json"
            settings = {
                "server": self.server_entry.get(),
                "port": self.port_entry.get(),
                "use_proxy": self.proxy_var.get(),
            }
            import json

            with open(settings_file, "w") as f:
                json.dump(settings, f)
        except:
            pass


def main():
    """Main entry point"""

    # Set VPN_PASSWORD environment variable if not set
    if not os.getenv("VPN_PASSWORD"):
        os.environ["VPN_PASSWORD"] = DEFAULT_PASSWORD

    # Check for required modules
    try:
        import PIL
        import pystray
    except ImportError:
        print("Installing required packages...")
        os.system("pip install pillow pystray")
        print("Please restart the application")
        sys.exit(1)

    # Create and run GUI
    app = VPNGui()

    # Save settings on close
    def on_closing():
        app.save_settings()
        app.quit_app()

    app.protocol("WM_DELETE_WINDOW", app.minimize_to_tray)

    # Start minimized if specified
    if "--minimized" in sys.argv:
        app.withdraw()

    app.mainloop()


if __name__ == "__main__":
    main()
