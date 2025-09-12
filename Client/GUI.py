#!/usr/bin/env python3
"""
Production VPN Client GUI
Modern, professional interface with auto-connect and system tray
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
from PIL import Image, ImageDraw, ImageFont
import pystray
from pystray import MenuItem as item
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ============================================================================
# PRODUCTION CONFIGURATION - EDIT THESE FOR YOUR DEPLOYMENT
# ============================================================================
VPN_SERVER = "localhost"  # Your VPN server address
VPN_PORT = 9999  # Your VPN server port
HTTP_PROXY_PORT = 8080  # Local HTTP proxy port
SOCKS_PROXY_PORT = 1080  # Local SOCKS5 proxy port
VPN_PASSWORD = "change_this_password_immediately"  # Your VPN password
COMPANY_NAME = "SecureVPN"  # Your company/product name
# ============================================================================

# Modern color scheme
COLORS = {
    "bg": "#0d1117",  # GitHub dark background
    "fg": "#c9d1d9",  # Light gray text
    "accent": "#58a6ff",  # Bright blue
    "success": "#3fb950",  # Green
    "error": "#f85149",  # Red
    "warning": "#d29922",  # Yellow
    "card_bg": "#161b22",  # Card background
    "border": "#30363d",  # Border color
    "text_secondary": "#8b949e",  # Secondary text
    "button_active": "#1f6feb",  # Active button
    "button_inactive": "#21262d",  # Inactive button
    "hover": "#30363d",  # Hover state
}


class VPNClient:
    """Core VPN client functionality"""

    def __init__(self, server_host, server_port, http_port=8080, socks_port=1080):
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
        password = os.getenv("VPN_PASSWORD", VPN_PASSWORD)
        salt = b"vpn_salt_2024_change_this"

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
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
            server_socket.settimeout(5)
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
            server.settimeout(1)
            server.bind(("0.0.0.0", self.http_port))
            server.listen(50)

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
            server.settimeout(1)
            server.bind(("127.0.0.1", self.socks_port))
            server.listen(50)

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
        # Implementation similar to handle_http_client
        # ... (abbreviated for space)
        pass

    def relay_tunnel_data(self, client, server):
        """Relay data between browser and VPN server"""
        server_buffer = b""

        try:
            while True:
                readers, _, _ = select.select([client, server], [], [], 1)

                if client in readers:
                    data = client.recv(4096)
                    if not data:
                        break

                    encrypted = self.encode_data(data)
                    if encrypted:
                        length_prefix = struct.pack("!I", len(encrypted))
                        server.send(length_prefix + encrypted)

                        with self.lock:
                            self.total_uploaded += len(data)

                if server in readers:
                    chunk = server.recv(4096)
                    if not chunk:
                        break

                    server_buffer += chunk

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


class WindowsProxyManager:
    """Windows system proxy management"""

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
        except:
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
        except:
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


def create_tray_icon():
    """Create a professional VPN shield icon for system tray"""
    # Create high-quality icon
    size = 64
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # Draw shield shape
    center_x, center_y = size // 2, size // 2
    shield_width = size * 0.6
    shield_height = size * 0.7

    # Shield path
    shield_points = [
        (center_x, center_y - shield_height // 2),  # Top
        (center_x + shield_width // 2, center_y - shield_height // 3),
        (center_x + shield_width // 2, center_y + shield_height // 4),
        (center_x, center_y + shield_height // 2),  # Bottom point
        (center_x - shield_width // 2, center_y + shield_height // 4),
        (center_x - shield_width // 2, center_y - shield_height // 3),
    ]

    # Draw gradient shield
    draw.polygon(shield_points, fill="#58a6ff", outline="#ffffff")

    # Draw lock icon in center
    lock_size = int(size * 0.25)
    lock_x = center_x - lock_size // 2
    lock_y = center_y - lock_size // 3

    # Lock body
    draw.rectangle(
        [lock_x, lock_y, lock_x + lock_size, lock_y + lock_size * 0.7], fill="#ffffff"
    )

    # Lock shackle
    draw.arc(
        [
            lock_x + lock_size // 4,
            lock_y - lock_size // 3,
            lock_x + 3 * lock_size // 4,
            lock_y + lock_size // 4,
        ],
        0,
        180,
        fill="#ffffff",
        width=2,
    )

    return image


class ModernVPNGui(tk.Tk):
    """Production VPN Client GUI"""

    def __init__(self):
        super().__init__()

        self.vpn_client = None
        self.is_protected = False
        self.stats_update_thread = None
        self.tray_icon = None
        self.auto_connect_thread = None

        # Configure window
        self.title(f"{COMPANY_NAME}")
        self.geometry("320x400")
        self.configure(bg=COLORS["bg"])
        self.resizable(False, False)

        # Remove window decorations for custom title bar - REMOVED THIS LINE
        # self.overrideredirect(True)

        # Make window draggable
        self.bind("<Button-1>", self.click_window)
        self.bind("<B1-Motion>", self.drag_window)

        # Set up window close protocol
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Create GUI
        self.create_widgets()

        # Setup system tray
        self.setup_system_tray()

        # Center window
        self.center_window()

        # Auto-connect on startup
        self.after(100, self.auto_connect)

    def on_closing(self):
        """Handle window closing with cleanup"""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.cleanup_on_exit()
            self.destroy()

    def cleanup_on_exit(self):
        """Clean up VPN and proxy settings on exit"""
        # Stop VPN if running
        if self.vpn_client:
            self.vpn_client.stop()

        # Disable Windows proxy
        WindowsProxyManager.disable()

        # Stop tray icon
        if self.tray_icon:
            self.tray_icon.stop()

    def click_window(self, event):
        self.offset_x = event.x
        self.offset_y = event.y

    def drag_window(self, event):
        x = self.winfo_pointerx() - self.offset_x
        y = self.winfo_pointery() - self.offset_y
        self.geometry(f"+{x}+{y}")

    def create_widgets(self):
        """Create modern UI widgets"""

        # Custom title bar - MODIFIED TO WORK WITH STANDARD WINDOW
        title_bar = tk.Frame(self, bg=COLORS["card_bg"], height=40)
        title_bar.pack(fill="x")
        title_bar.pack_propagate(False)

        # Title
        title = tk.Label(
            title_bar,
            text=f"  {COMPANY_NAME}",
            bg=COLORS["card_bg"],
            fg=COLORS["fg"],
            font=("Segoe UI", 11, "bold"),
            anchor="w",
        )
        title.pack(side="left", fill="both", expand=True, padx=10)

        # Minimize button
        min_btn = tk.Button(
            title_bar,
            text="─",
            bg=COLORS["card_bg"],
            fg=COLORS["text_secondary"],
            font=("Segoe UI", 12),
            bd=0,
            padx=15,
            activebackground=COLORS["hover"],
            activeforeground=COLORS["fg"],
            command=self.minimize_to_tray,
        )
        min_btn.pack(side="right")

        # Close button - MODIFIED TO USE on_closing
        close_btn = tk.Button(
            title_bar,
            text="✕",
            bg=COLORS["card_bg"],
            fg=COLORS["text_secondary"],
            font=("Segoe UI", 12),
            bd=0,
            padx=15,
            activebackground=COLORS["error"],
            activeforeground=COLORS["fg"],
            command=self.on_closing,
        )
        close_btn.pack(side="right")

        # Main container
        main_frame = tk.Frame(self, bg=COLORS["bg"])
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Shield icon and status
        shield_frame = tk.Frame(main_frame, bg=COLORS["bg"])
        shield_frame.pack(pady=(0, 20))

        # Large shield icon (using canvas)
        self.shield_canvas = tk.Canvas(
            shield_frame, width=80, height=80, bg=COLORS["bg"], highlightthickness=0
        )
        self.shield_canvas.pack()
        self.draw_shield(False)

        # Status text
        self.status_label = tk.Label(
            main_frame,
            text="UNPROTECTED",
            bg=COLORS["bg"],
            fg=COLORS["error"],
            font=("Segoe UI", 14, "bold"),
        )
        self.status_label.pack(pady=(0, 5))

        self.status_detail = tk.Label(
            main_frame,
            text="Your connection is not secure",
            bg=COLORS["bg"],
            fg=COLORS["text_secondary"],
            font=("Segoe UI", 9),
        )
        self.status_detail.pack(pady=(0, 20))

        # Toggle button
        self.toggle_btn = tk.Button(
            main_frame,
            text="ENABLE PROTECTION",
            bg=COLORS["button_inactive"],
            fg=COLORS["fg"],
            font=("Segoe UI", 11, "bold"),
            relief="flat",
            cursor="hand2",
            bd=0,
            activebackground=COLORS["hover"],
            activeforeground=COLORS["fg"],
            command=self.toggle_protection,
            pady=12,
        )
        self.toggle_btn.pack(fill="x", pady=(0, 20))

        # Stats section
        stats_frame = tk.Frame(main_frame, bg=COLORS["card_bg"])
        stats_frame.pack(fill="x", pady=(0, 10))

        # Stats title
        tk.Label(
            stats_frame,
            text="CURRENT SESSION",
            bg=COLORS["card_bg"],
            fg=COLORS["text_secondary"],
            font=("Segoe UI", 9),
        ).pack(pady=(10, 5))

        # Stats container
        stats_container = tk.Frame(stats_frame, bg=COLORS["card_bg"])
        stats_container.pack(pady=(0, 10))

        # Upload
        upload_frame = tk.Frame(stats_container, bg=COLORS["card_bg"])
        upload_frame.pack(side="left", padx=20)

        tk.Label(
            upload_frame,
            text="↑",
            bg=COLORS["card_bg"],
            fg=COLORS["success"],
            font=("Segoe UI", 16),
        ).pack()
        self.upload_label = tk.Label(
            upload_frame,
            text="0.00 MB",
            bg=COLORS["card_bg"],
            fg=COLORS["fg"],
            font=("Segoe UI", 10),
        )
        self.upload_label.pack()

        # Download
        download_frame = tk.Frame(stats_container, bg=COLORS["card_bg"])
        download_frame.pack(side="left", padx=20)

        tk.Label(
            download_frame,
            text="↓",
            bg=COLORS["card_bg"],
            fg=COLORS["accent"],
            font=("Segoe UI", 16),
        ).pack()
        self.download_label = tk.Label(
            download_frame,
            text="0.00 MB",
            bg=COLORS["card_bg"],
            fg=COLORS["fg"],
            font=("Segoe UI", 10),
        )
        self.download_label.pack()

        # Server info (subtle)
        server_info = tk.Label(
            main_frame,
            text=f"Server: {VPN_SERVER}",
            bg=COLORS["bg"],
            fg=COLORS["text_secondary"],
            font=("Segoe UI", 8),
        )
        server_info.pack(side="bottom")

    def draw_shield(self, protected):
        """Draw shield icon on canvas"""
        self.shield_canvas.delete("all")

        # Shield color based on status
        shield_color = COLORS["success"] if protected else COLORS["text_secondary"]

        # Draw shield
        points = [40, 10, 65, 20, 65, 45, 40, 70, 15, 45, 15, 20]
        self.shield_canvas.create_polygon(points, fill=shield_color, outline="")

        # Draw lock
        if protected:
            # Locked padlock
            self.shield_canvas.create_rectangle(
                30, 35, 50, 50, fill=COLORS["bg"], outline=""
            )
            self.shield_canvas.create_arc(
                32,
                28,
                48,
                44,
                start=0,
                extent=180,
                style="arc",
                outline=COLORS["bg"],
                width=3,
            )
        else:
            # Unlocked padlock
            self.shield_canvas.create_rectangle(
                30, 35, 50, 50, fill=COLORS["bg"], outline=""
            )
            self.shield_canvas.create_arc(
                32,
                24,
                48,
                40,
                start=30,
                extent=150,
                style="arc",
                outline=COLORS["bg"],
                width=3,
            )

    def auto_connect(self):
        """Auto-connect on startup"""
        self.auto_connect_thread = threading.Thread(
            target=self._auto_connect_thread, daemon=True
        )
        self.auto_connect_thread.start()

    def _auto_connect_thread(self):
        """Auto-connect in background thread"""
        time.sleep(0.5)  # Small delay for UI to initialize

        # Create VPN client
        self.vpn_client = VPNClient(
            VPN_SERVER, VPN_PORT, HTTP_PROXY_PORT, SOCKS_PROXY_PORT
        )

        # Test connection
        if self.vpn_client.test_connection():
            # Start VPN
            self.vpn_client.start()

            # Enable Windows proxy
            WindowsProxyManager.enable("localhost", HTTP_PROXY_PORT)

            # Update UI
            self.after(0, self._update_ui_connected)

            # Start stats updater
            self.stats_update_thread = threading.Thread(
                target=self._update_stats_loop, daemon=True
            )
            self.stats_update_thread.start()
        else:
            # Connection failed
            self.after(0, self._connection_failed)

    def _update_ui_connected(self):
        """Update UI for connected state"""
        self.is_protected = True
        self.draw_shield(True)
        self.status_label.config(text="PROTECTED", fg=COLORS["success"])
        self.status_detail.config(text="Your connection is secure")
        self.toggle_btn.config(text="DISABLE PROTECTION", bg=COLORS["button_active"])

        if self.tray_icon:
            self.tray_icon.title = f"{COMPANY_NAME} - Protected"

    def _update_ui_disconnected(self):
        """Update UI for disconnected state"""
        self.is_protected = False
        self.draw_shield(False)
        self.status_label.config(text="UNPROTECTED", fg=COLORS["error"])
        self.status_detail.config(text="Your connection is not secure")
        self.toggle_btn.config(text="ENABLE PROTECTION", bg=COLORS["button_inactive"])

        # Reset stats
        self.upload_label.config(text="0.00 MB")
        self.download_label.config(text="0.00 MB")

        if self.tray_icon:
            self.tray_icon.title = f"{COMPANY_NAME} - Unprotected"

    def _connection_failed(self):
        """Handle connection failure"""
        self._update_ui_disconnected()
        self.status_detail.config(text="Cannot connect to VPN server")
        messagebox.showerror(
            f"{COMPANY_NAME}",
            f"Cannot connect to VPN server.\nPlease check your connection and try again.",
        )

    def toggle_protection(self):
        """Toggle VPN protection"""
        if not self.is_protected:
            self.enable_protection()
        else:
            self.disable_protection()

    def enable_protection(self):
        """Enable VPN protection"""
        self.toggle_btn.config(state="disabled", text="CONNECTING...")

        thread = threading.Thread(target=self._enable_protection_thread, daemon=True)
        thread.start()

    def _enable_protection_thread(self):
        """Enable protection in thread"""
        if not self.vpn_client:
            self.vpn_client = VPNClient(
                VPN_SERVER, VPN_PORT, HTTP_PROXY_PORT, SOCKS_PROXY_PORT
            )

        if self.vpn_client.test_connection():
            self.vpn_client.start()
            WindowsProxyManager.enable("localhost", HTTP_PROXY_PORT)

            self.after(0, self._update_ui_connected)
            self.after(0, lambda: self.toggle_btn.config(state="normal"))

            # Start stats updater
            if not self.stats_update_thread or not self.stats_update_thread.is_alive():
                self.stats_update_thread = threading.Thread(
                    target=self._update_stats_loop, daemon=True
                )
                self.stats_update_thread.start()
        else:
            self.after(0, self._connection_failed)
            self.after(
                0,
                lambda: self.toggle_btn.config(
                    state="normal", text="ENABLE PROTECTION"
                ),
            )

    def disable_protection(self):
        """Disable VPN protection"""
        if self.vpn_client:
            self.vpn_client.stop()

        WindowsProxyManager.disable()

        self._update_ui_disconnected()

    def _update_stats_loop(self):
        """Update statistics in loop"""
        while self.is_protected and self.vpn_client and self.vpn_client.active:
            if self.vpn_client:
                upload_mb = self.vpn_client.total_uploaded / (1024 * 1024)
                download_mb = self.vpn_client.total_downloaded / (1024 * 1024)

                self.after(0, self.upload_label.config, {"text": f"{upload_mb:.2f} MB"})
                self.after(
                    0, self.download_label.config, {"text": f"{download_mb:.2f} MB"}
                )

            time.sleep(0.5)

    def setup_system_tray(self):
        """Setup system tray icon"""
        # Create icon
        image = create_tray_icon()

        # Create menu
        menu = pystray.Menu(
            item("Show", self.show_window, default=True),
            item(
                "Enable Protection",
                lambda: self.after(0, self.enable_protection),
                visible=lambda item: not self.is_protected,
            ),
            item(
                "Disable Protection",
                lambda: self.after(0, self.disable_protection),
                visible=lambda item: self.is_protected,
            ),
            pystray.Menu.SEPARATOR,
            item("Exit", self.quit_app),
        )

        # Create tray icon
        self.tray_icon = pystray.Icon(
            COMPANY_NAME, image, f"{COMPANY_NAME} - Unprotected", menu
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
        self.cleanup_on_exit()
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


def main():
    """Main entry point"""

    # Set VPN_PASSWORD environment variable
    os.environ["VPN_PASSWORD"] = VPN_PASSWORD

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
    app = ModernVPNGui()
    app.mainloop()


if __name__ == "__main__":
    main()
