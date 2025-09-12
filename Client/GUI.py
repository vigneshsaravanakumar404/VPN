#!/usr/bin/env python3
"""
VPN Client GUI
Main graphical user interface for the VPN client
"""

import tkinter as tk
from tkinter import messagebox
import threading
import time
import sys

from config import *
from vpn_client import VPNClient
from proxy_manager import WindowsProxyManager
from utils import setup_system_tray, draw_shield_on_canvas


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
        self.title(COMPANY_NAME)
        self.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.configure(bg=COLORS["bg"])
        self.resizable(WINDOW_RESIZABLE, WINDOW_RESIZABLE)

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

    def minimize_to_tray(self):
        """Minimize window to system tray (hides from taskbar)"""
        self.withdraw()

    def show_window(self):
        """Show window from tray"""
        self.deiconify()
        self.lift()
        self.focus_force()

    def click_window(self, event):
        """Handle window click for dragging"""
        self.offset_x = event.x
        self.offset_y = event.y

    def drag_window(self, event):
        """Handle window dragging"""
        x = self.winfo_pointerx() - self.offset_x
        y = self.winfo_pointery() - self.offset_y
        self.geometry(f"+{x}+{y}")

    def create_widgets(self):
        """Create modern UI widgets"""

        # Custom title bar
        self.create_title_bar()

        # Main container
        main_frame = tk.Frame(self, bg=COLORS["bg"])
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Shield icon and status
        self.create_shield_section(main_frame)

        # Toggle button
        self.create_toggle_button(main_frame)

        # Stats section
        self.create_stats_section(main_frame)

        # Server info
        self.create_server_info(main_frame)

    def create_title_bar(self):
        """Create custom title bar"""
        title_bar = tk.Frame(self, bg=COLORS["card_bg"], height=40)
        title_bar.pack(fill="x")
        title_bar.pack_propagate(False)

        # Title
        title = tk.Label(
            title_bar,
            text=f"  {COMPANY_NAME}",
            bg=COLORS["card_bg"],
            fg=COLORS["fg"],
            font=FONTS["title"],
            anchor="w",
        )
        title.pack(side="left", fill="both", expand=True, padx=10)

        # Minimize button
        min_btn = tk.Button(
            title_bar,
            text="─",
            bg=COLORS["card_bg"],
            fg=COLORS["text_secondary"],
            font=FONTS["window_controls"],
            bd=0,
            padx=15,
            activebackground=COLORS["hover"],
            activeforeground=COLORS["fg"],
            command=self.minimize_to_tray,
        )
        min_btn.pack(side="right")

        # Close button
        close_btn = tk.Button(
            title_bar,
            text="✕",
            bg=COLORS["card_bg"],
            fg=COLORS["text_secondary"],
            font=FONTS["window_controls"],
            bd=0,
            padx=15,
            activebackground=COLORS["error"],
            activeforeground=COLORS["fg"],
            command=self.on_closing,
        )
        close_btn.pack(side="right")

    def create_shield_section(self, parent):
        """Create shield icon and status section"""
        shield_frame = tk.Frame(parent, bg=COLORS["bg"])
        shield_frame.pack(pady=(0, 20))

        # Large shield icon (using canvas)
        self.shield_canvas = tk.Canvas(
            shield_frame, width=80, height=80, bg=COLORS["bg"], highlightthickness=0
        )
        self.shield_canvas.pack()
        draw_shield_on_canvas(self.shield_canvas, False)

        # Status text
        self.status_label = tk.Label(
            parent,
            text="UNPROTECTED",
            bg=COLORS["bg"],
            fg=COLORS["error"],
            font=FONTS["status"],
        )
        self.status_label.pack(pady=(0, 5))

        self.status_detail = tk.Label(
            parent,
            text="Your connection is not secure",
            bg=COLORS["bg"],
            fg=COLORS["text_secondary"],
            font=FONTS["detail"],
        )
        self.status_detail.pack(pady=(0, 20))

    def create_toggle_button(self, parent):
        """Create protection toggle button"""
        self.toggle_btn = tk.Button(
            parent,
            text="ENABLE PROTECTION",
            bg=COLORS["button_inactive"],
            fg=COLORS["fg"],
            font=FONTS["button"],
            relief="flat",
            cursor="hand2",
            bd=0,
            activebackground=COLORS["hover"],
            activeforeground=COLORS["fg"],
            command=self.toggle_protection,
            pady=12,
        )
        self.toggle_btn.pack(fill="x", pady=(0, 20))

    def create_stats_section(self, parent):
        """Create statistics section"""
        stats_frame = tk.Frame(parent, bg=COLORS["card_bg"])
        stats_frame.pack(fill="x", pady=(0, 10))

        # Stats title
        tk.Label(
            stats_frame,
            text="CURRENT SESSION",
            bg=COLORS["card_bg"],
            fg=COLORS["text_secondary"],
            font=FONTS["detail"],
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
            font=FONTS["icon"],
        ).pack()

        self.upload_label = tk.Label(
            upload_frame,
            text="0.00 MB",
            bg=COLORS["card_bg"],
            fg=COLORS["fg"],
            font=FONTS["stats"],
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
            font=FONTS["icon"],
        ).pack()

        self.download_label = tk.Label(
            download_frame,
            text="0.00 MB",
            bg=COLORS["card_bg"],
            fg=COLORS["fg"],
            font=FONTS["stats"],
        )
        self.download_label.pack()

    def create_server_info(self, parent):
        """Create server info label"""
        server_info = tk.Label(
            parent,
            text=f"Server: {VPN_SERVER}",
            bg=COLORS["bg"],
            fg=COLORS["text_secondary"],
            font=FONTS["small"],
        )
        server_info.pack(side="bottom")

    def auto_connect(self):
        """Auto-connect on startup"""
        self.auto_connect_thread = threading.Thread(
            target=self._auto_connect_thread, daemon=True
        )
        self.auto_connect_thread.start()

    def _auto_connect_thread(self):
        """Auto-connect in background thread"""
        time.sleep(AUTO_CONNECT_DELAY)

        # Create VPN client
        self.vpn_client = VPNClient()

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
        draw_shield_on_canvas(self.shield_canvas, True)
        self.status_label.config(text="PROTECTED", fg=COLORS["success"])
        self.status_detail.config(text="Your connection is secure")
        self.toggle_btn.config(text="DISABLE PROTECTION", bg=COLORS["button_active"])

        if self.tray_icon:
            self.tray_icon.title = f"{COMPANY_NAME} - Protected"

    def _update_ui_disconnected(self):
        """Update UI for disconnected state"""
        self.is_protected = False
        draw_shield_on_canvas(self.shield_canvas, False)
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
            COMPANY_NAME,
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
            self.vpn_client = VPNClient()

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
                upload, download = self.vpn_client.get_stats()
                upload_mb = upload / (1024 * 1024)
                download_mb = download / (1024 * 1024)

                self.after(0, self.upload_label.config, {"text": f"{upload_mb:.2f} MB"})
                self.after(
                    0, self.download_label.config, {"text": f"{download_mb:.2f} MB"}
                )

            time.sleep(STATS_UPDATE_INTERVAL)

    def setup_system_tray(self):
        """Setup system tray icon"""
        self.tray_icon = setup_system_tray(
            self,
            self.show_window,
            lambda: self.after(0, self.enable_protection),
            lambda: self.after(0, self.disable_protection),
            self.quit_app,
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
