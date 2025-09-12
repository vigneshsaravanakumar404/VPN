#!/usr/bin/env python3
"""
VPN Client Application
Main entry point for the production VPN client
"""

import os
import sys
import tkinter as tk
from tkinter import messagebox

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import VPN_PASSWORD
from gui import ModernVPNGui


def check_dependencies():
    """Check and install required dependencies"""
    required_packages = {
        "PIL": "pillow",
        "pystray": "pystray",
        "cryptography": "cryptography",
    }

    missing_packages = []

    for module, package in required_packages.items():
        try:
            __import__(module)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        print(f"Missing required packages: {', '.join(missing_packages)}")
        print("Installing required packages...")

        import subprocess

        for package in missing_packages:
            subprocess.run([sys.executable, "-m", "pip", "install", package])

        print("\nPackages installed. Please restart the application.")
        sys.exit(0)


def main():
    """Main entry point"""

    # Check for required dependencies
    check_dependencies()

    # Set VPN_PASSWORD environment variable
    os.environ["VPN_PASSWORD"] = VPN_PASSWORD

    try:
        # Create and run GUI
        app = ModernVPNGui()
        app.mainloop()

    except Exception as e:
        # Show error dialog if GUI fails to start
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "VPN Client Error",
            f"Failed to start VPN client:\n\n{str(e)}\n\nPlease check the configuration and try again.",
        )
        root.destroy()
        sys.exit(1)


if __name__ == "__main__":
    main()
