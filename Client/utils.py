#!/usr/bin/env python3
"""
Utility Functions
Helper functions for the VPN client application
"""

from PIL import Image, ImageDraw
import pystray
from pystray import MenuItem as item
from config import COLORS, COMPANY_NAME, TRAY_ICON_SIZE


def create_tray_icon():
    """Create a professional VPN shield icon for system tray

    Returns:
        PIL.Image: Shield icon image
    """
    size = TRAY_ICON_SIZE
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # Calculate dimensions
    center_x, center_y = size // 2, size // 2
    shield_width = size * 0.6
    shield_height = size * 0.7

    # Shield path points
    shield_points = [
        (center_x, center_y - shield_height // 2),  # Top
        (center_x + shield_width // 2, center_y - shield_height // 3),
        (center_x + shield_width // 2, center_y + shield_height // 4),
        (center_x, center_y + shield_height // 2),  # Bottom point
        (center_x - shield_width // 2, center_y + shield_height // 4),
        (center_x - shield_width // 2, center_y - shield_height // 3),
    ]

    # Draw gradient shield
    draw.polygon(shield_points, fill=COLORS["accent"], outline="#ffffff")

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


def format_bytes(bytes_value):
    """Format bytes to human readable format

    Args:
        bytes_value: Number of bytes

    Returns:
        str: Formatted string (e.g., "1.23 MB")
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def setup_system_tray(
    parent, show_callback, enable_callback, disable_callback, quit_callback
):
    """Setup system tray icon with menu

    Args:
        parent: Parent window object
        show_callback: Function to call when showing window
        enable_callback: Function to call when enabling protection
        disable_callback: Function to call when disabling protection
        quit_callback: Function to call when quitting

    Returns:
        pystray.Icon: System tray icon object
    """
    # Create icon
    image = create_tray_icon()

    # Create menu with Show, Enable/Disable, and Quit options
    menu = pystray.Menu(
        item("Show", show_callback, default=True),
        item(
            "Enable Protection",
            enable_callback,
            visible=lambda item: not parent.is_protected,
        ),
        item(
            "Disable Protection",
            disable_callback,
            visible=lambda item: parent.is_protected,
        ),
        pystray.Menu.SEPARATOR,
        item("Quit", quit_callback),  # Quit option for right-click menu
    )

    # Create tray icon
    tray_icon = pystray.Icon(COMPANY_NAME, image, f"{COMPANY_NAME} - Unprotected", menu)

    return tray_icon


def draw_shield_on_canvas(canvas, protected):
    """Draw shield icon on tkinter canvas

    Args:
        canvas: tkinter Canvas widget
        protected: bool indicating protection status
    """
    canvas.delete("all")

    # Shield color based on status
    shield_color = COLORS["success"] if protected else COLORS["text_secondary"]

    # Draw shield
    points = [40, 10, 65, 20, 65, 45, 40, 70, 15, 45, 15, 20]
    canvas.create_polygon(points, fill=shield_color, outline="")

    # Draw lock
    if protected:
        # Locked padlock
        canvas.create_rectangle(30, 35, 50, 50, fill=COLORS["bg"], outline="")
        canvas.create_arc(
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
        canvas.create_rectangle(30, 35, 50, 50, fill=COLORS["bg"], outline="")
        canvas.create_arc(
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
