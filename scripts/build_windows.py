"""Build the Windows portable executable on a native Windows Python runner."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from desktop_sniffer import __version__

if sys.platform != "win32":
    raise SystemExit("This build must run on Windows")
args = [
    sys.executable,
    "-m",
    "PyInstaller",
    "--noconfirm",
    "--clean",
    "--onefile",
    "--windowed",
    "--name",
    "Snare-Windows",
    "--icon",
    "src/desktop_sniffer/assets/icon.ico",
    "--add-data",
    "src/desktop_sniffer:desktop_sniffer",
    "--collect-all",
    "mitmproxy",
    "--collect-all",
    "mitmproxy_rs",
    "--collect-all",
    "mitmproxy_windows",
    "--collect-all",
    "qrcode",
    "--hidden-import",
    "desktop_sniffer.infrastructure.mitmproxy.addon_entry",
    "--exclude-module",
    "PySide6.QtQml",
    "--exclude-module",
    "PySide6.QtQuick",
    "--exclude-module",
    "PySide6.QtPdf",
    "--exclude-module",
    "PySide6.QtOpenGL",
    "--exclude-module",
    "PySide6.QtVirtualKeyboard",
    "--exclude-module",
    "pytest",
    "--exclude-module",
    "IPython",
    "src/desktop_sniffer/app.py",
]
subprocess.run(args, check=True)
exe = Path("dist/Snare-Windows.exe")
digest = hashlib.sha256(exe.read_bytes()).hexdigest()
Path("dist/SHA256SUMS").write_text(f"{digest}  {exe.name}\n", encoding="ascii")
Path("dist/BUILD-INFO.json").write_text(
    json.dumps(
        {
            "version": __version__,
            "python": sys.version,
            "platform": sys.platform,
            "sha256": digest,
        },
        indent=2,
    ),
    encoding="utf-8",
)
Path("dist/README.txt").write_text(
    f"Snare {__version__} — Windows x64 portable\n\nRun Snare-Windows.exe. Python is not required.\nUse Connection / Storage to enable Windows System Proxy after the engine is ready.\nFor HTTPS trust the local mitmproxy CA; Mobile Setup opens its folder.\nClose Snare normally to restore previous proxy settings.\nThis review build is not Authenticode-signed.\n",
    encoding="utf-8",
)
