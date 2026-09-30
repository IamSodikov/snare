"""Snapshot/restore the user's Windows proxy, including stale-session recovery."""

import ctypes
import json
import sys
from pathlib import Path

from desktop_sniffer.infrastructure.persistence.atomic_json import atomic_json

KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
VALUES = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect")


class SystemProxy:
    def __init__(self, recovery_path: Path):
        self.recovery_path = recovery_path
        self.active = False

    @staticmethod
    def supported():
        return sys.platform == "win32"

    @staticmethod
    def _read():
        import winreg

        values = {}
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_READ) as key:
            for name in VALUES:
                try:
                    value, kind = winreg.QueryValueEx(key, name)
                    values[name] = [value, kind]
                except FileNotFoundError:
                    values[name] = None
        return values

    @staticmethod
    def _write(values):
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_SET_VALUE
        ) as key:
            for name, entry in values.items():
                if entry is None:
                    try:
                        winreg.DeleteValue(key, name)
                    except FileNotFoundError:
                        pass
                else:
                    winreg.SetValueEx(key, name, 0, entry[1], entry[0])
        for option in (39, 37):
            if not ctypes.windll.wininet.InternetSetOptionW(0, option, 0, 0):
                raise OSError("Windows proxy yangilanishi qo‘llanmadi")

    def enable(self, port, host="127.0.0.1"):
        if not self.supported():
            raise RuntimeError("Avtomatik System Proxy faqat Windows’da mavjud")
        import winreg

        if not self.recovery_path.exists():
            atomic_json(self.recovery_path, {"version": 1, "before": self._read()})
        record = json.loads(self.recovery_path.read_text(encoding="utf-8"))
        owned = {
            "ProxyEnable": [1, winreg.REG_DWORD],
            "ProxyServer": [f"{host}:{port}", winreg.REG_SZ],
            "ProxyOverride": ["<local>", winreg.REG_SZ],
            "AutoConfigURL": None,
            "AutoDetect": [0, winreg.REG_DWORD],
        }
        record["owned"] = owned
        atomic_json(self.recovery_path, record)
        try:
            self._write(owned)
        except Exception:
            self._write(record["before"])
            self.recovery_path.unlink(missing_ok=True)
            raise
        self.active = True

    def restore(self):
        if not self.supported() or not self.recovery_path.exists():
            self.active = False
            return
        record = json.loads(self.recovery_path.read_text(encoding="utf-8"))
        current = self._read()
        # Preserve any settings explicitly changed by the user during the session.
        restore = {
            name: value
            for name, value in record["before"].items()
            if current.get(name) == record.get("owned", {}).get(name)
        }
        self._write(restore)
        self.recovery_path.unlink(missing_ok=True)
        self.active = False


def set_windows_proxy(enable, host="127.0.0.1", port=8080):
    from desktop_sniffer.core.paths import application_data_dir

    proxy = SystemProxy(application_data_dir() / "proxy-recovery.json")
    if enable:
        proxy.enable(port, host)
    else:
        proxy.restore()
