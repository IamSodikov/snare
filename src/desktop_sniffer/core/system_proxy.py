import sys

def set_windows_proxy(enable: bool, host: str = "127.0.0.1", port: int = 8080):
    if sys.platform != "win32":
        return

    try:
        import winreg
        import ctypes

        internet_settings = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0,
            winreg.KEY_ALL_ACCESS,
        )

        winreg.SetValueEx(internet_settings, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
        
        if enable:
            winreg.SetValueEx(internet_settings, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
            # Optional: Ignore local addresses
            winreg.SetValueEx(internet_settings, "ProxyOverride", 0, winreg.REG_SZ, "<local>")

        winreg.CloseKey(internet_settings)

        # Notify Windows about the change so it applies immediately
        internet_option_settings_changed = 39
        internet_option_refresh = 37
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, internet_option_settings_changed, 0, 0)
        wininet.InternetSetOptionW(0, internet_option_refresh, 0, 0)

    except Exception as exc:
        print(f"Failed to set system proxy: {exc}")
