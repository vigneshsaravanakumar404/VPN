#!/usr/bin/env python3
"""
VPN Client Configuration
Central configuration file for all VPN client settings
"""

# ============================================================================
# PRODUCTION CONFIGURATION - EDIT THESE FOR YOUR DEPLOYMENT
# ============================================================================
VPN_SERVER = "localhost"  # Your VPN server address
VPN_PORT = 9999  # Your VPN server port
HTTP_PROXY_PORT = 8080  # Local HTTP proxy port
SOCKS_PROXY_PORT = 1080  # Local SOCKS5 proxy port
VPN_PASSWORD = "change_this_password_immediately"  # Your VPN password
COMPANY_NAME = "SecureVPN"  # Your company/product name

# Encryption settings
ENCRYPTION_SALT = b"vpn_salt_2024_change_this"
ENCRYPTION_ITERATIONS = 100000

# ============================================================================
# UI CONFIGURATION
# ============================================================================

# Window settings
WINDOW_WIDTH = 320
WINDOW_HEIGHT = 470
WINDOW_RESIZABLE = False

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

# Font settings
FONTS = {
    "title": ("Segoe UI", 11, "bold"),
    "status": ("Segoe UI", 14, "bold"),
    "detail": ("Segoe UI", 9),
    "button": ("Segoe UI", 11, "bold"),
    "stats": ("Segoe UI", 10),
    "small": ("Segoe UI", 8),
    "icon": ("Segoe UI", 16),
    "window_controls": ("Segoe UI", 12),
}

# ============================================================================
# NETWORK CONFIGURATION
# ============================================================================

# Timeouts (in seconds)
CONNECTION_TIMEOUT = 5
CLIENT_TIMEOUT = 10
SOCKET_TIMEOUT = 1

# Buffer sizes
BUFFER_SIZE = 4096
MAX_PACKET_SIZE = 1024 * 1024  # 1MB

# Proxy settings
PROXY_LISTEN_ADDRESS = "0.0.0.0"  # For HTTP proxy
SOCKS_LISTEN_ADDRESS = "127.0.0.1"  # For SOCKS5 proxy
PROXY_LISTEN_BACKLOG = 50

# Windows proxy bypass list
PROXY_BYPASS = "localhost;127.0.0.1;*.local;<local>"

# ============================================================================
# SYSTEM CONFIGURATION
# ============================================================================

# Registry key for Windows proxy settings
INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# Stats update interval (seconds)
STATS_UPDATE_INTERVAL = 0.5

# Auto-connect delay (seconds)
AUTO_CONNECT_DELAY = 0.5

# Tray icon size
TRAY_ICON_SIZE = 64
