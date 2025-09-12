#!/usr/bin/env python3
"""
Windows Proxy Manager
Handles Windows system proxy configuration
"""

import winreg
import ctypes
from config import INTERNET_SETTINGS_KEY, PROXY_BYPASS


class WindowsProxyManager:
    """Windows system proxy management"""

    @staticmethod
    def enable(server, port):
        """Enable Windows system proxy

        Args:
            server: Proxy server address
            port: Proxy server port

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            proxy_server = f"{server}:{port}"

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                INTERNET_SETTINGS_KEY,
                0,
                winreg.KEY_WRITE,
            )

            # Enable proxy
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)

            # Set proxy server
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_server)

            # Set bypass list
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, PROXY_BYPASS)

            # Disable auto-detect
            winreg.SetValueEx(key, "AutoDetect", 0, winreg.REG_DWORD, 0)

            winreg.CloseKey(key)

            # Refresh settings
            WindowsProxyManager._refresh()

            return True

        except Exception as e:
            print(f"Failed to enable proxy: {e}")
            return False

    @staticmethod
    def disable():
        """Disable Windows system proxy

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                INTERNET_SETTINGS_KEY,
                0,
                winreg.KEY_WRITE,
            )

            # Disable proxy
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)

            winreg.CloseKey(key)

            # Refresh settings
            WindowsProxyManager._refresh()

            return True

        except Exception as e:
            print(f"Failed to disable proxy: {e}")
            return False

    @staticmethod
    def get_status():
        """Get current proxy status

        Returns:
            dict: Current proxy settings or None if error
        """
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                INTERNET_SETTINGS_KEY,
                0,
                winreg.KEY_READ,
            )

            proxy_enabled = winreg.QueryValueEx(key, "ProxyEnable")[0]

            settings = {"enabled": bool(proxy_enabled), "server": None, "bypass": None}

            if proxy_enabled:
                try:
                    settings["server"] = winreg.QueryValueEx(key, "ProxyServer")[0]
                    settings["bypass"] = winreg.QueryValueEx(key, "ProxyOverride")[0]
                except:
                    pass

            winreg.CloseKey(key)
            return settings

        except Exception as e:
            print(f"Failed to get proxy status: {e}")
            return None

    @staticmethod
    def _refresh():
        """Refresh Internet settings to apply proxy changes"""
        try:
            internet = ctypes.windll.Wininet

            # INTERNET_OPTION_SETTINGS_CHANGED
            internet.InternetSetOptionW(0, 39, 0, 0)

            # INTERNET_OPTION_REFRESH
            internet.InternetSetOptionW(0, 37, 0, 0)

        except Exception as e:
            print(f"Failed to refresh Internet settings: {e}")
            pass
