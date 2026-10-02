"""Verify HTTPS and published SHA-256 manifests; never silently downgrade TLS."""

import hashlib
import json
import ssl
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from packaging.version import InvalidVersion, Version
from PySide6.QtCore import QObject, QThread, Signal

from desktop_sniffer import __version__

GITHUB_REPO = "IamSodikov/snare"
ALLOWED_HOSTS = {
    "github.com",
    "api.github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
}


def get_ssl_context():
    return ssl.create_default_context()


def valid_url(url):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in ALLOWED_HOSTS
        or parsed.username
    ):
        raise ValueError("Yangilanish manzili ishonchli GitHub HTTPS manzili emas")
    return url


class SecureRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        valid_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_url(url, timeout=15):
    valid_url(url)
    opener = urllib.request.build_opener(
        SecureRedirect(), urllib.request.HTTPSHandler(context=get_ssl_context())
    )
    return opener.open(
        urllib.request.Request(url, headers={"User-Agent": "Snare-Updater"}),
        timeout=timeout,
    )


class Updater(QObject):
    update_available = Signal(str, str, str, str)
    error = Signal(str)

    def check_for_updates(self):
        if not getattr(sys, "frozen", False):
            return

        def check():
            try:
                with open_url(
                    f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
                ) as response:
                    data = json.loads(response.read(2 * 1024 * 1024))
                version = data.get("tag_name", "")
                if data.get("prerelease") or Version(version.lstrip("v")) <= Version(
                    __version__.lstrip("v")
                ):
                    return
                target = {
                    "win32": "Snare-Windows.exe",
                    "darwin": "Snare-MacOS.zip",
                }.get(sys.platform, "Snare-Linux")
                assets = {
                    a["name"]: a["browser_download_url"] for a in data.get("assets", [])
                }
                if target not in assets or "SHA256SUMS" not in assets:
                    self.error.emit(
                        "Release’da tekshiruv manifesti yo‘q; avtomatik yuklash bajarilmadi"
                    )
                    return
                with open_url(assets["SHA256SUMS"]) as response:
                    manifest = response.read(65536).decode("ascii")
                hashes = {
                    line.split()[-1].lstrip("*"): line.split()[0]
                    for line in manifest.splitlines()
                    if len(line.split()) == 2
                }
                expected = hashes.get(target, "")
                if len(expected) != 64 or any(
                    c not in "0123456789abcdefABCDEF" for c in expected
                ):
                    raise ValueError("SHA256 manifesti noto‘g‘ri")
                self.update_available.emit(
                    version, valid_url(assets[target]), data.get("body", ""), expected
                )
            except (OSError, ValueError, InvalidVersion) as exc:
                self.error.emit(f"Update check: {exc}")

        threading.Thread(target=check, daemon=True).start()


class DownloadThread(QThread):
    progress = Signal(int)
    completed = Signal(str)
    error = Signal(str)

    def __init__(self, url, expected_hash, parent=None):
        super().__init__(parent)
        self.url = valid_url(url)
        self.expected_hash = expected_hash.lower()

    def run(self):
        path = None
        try:
            directory = Path(tempfile.mkdtemp(prefix="snare-update-"))
            path = directory / (
                "Snare-Windows.exe" if sys.platform == "win32" else "Snare-update"
            )
            digest = hashlib.sha256()
            with open_url(self.url) as response, path.open("wb") as output:
                total = int(response.headers.get("Content-Length", 0))
                downloaded = 0
                while True:
                    if self.isInterruptionRequested():
                        raise InterruptedError("Yuklash bekor qilindi")
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if downloaded > 512 * 1024 * 1024:
                        raise ValueError("Update hajmi limitdan katta")
                    output.write(chunk)
                    digest.update(chunk)
                    if total:
                        self.progress.emit(min(99, downloaded * 100 // total))
                if total and downloaded != total:
                    raise ValueError("Yuklash to‘liq tugamadi")
            if digest.hexdigest() != self.expected_hash:
                raise ValueError("SHA256 mos kelmadi — fayl rad etildi")
            self.progress.emit(100)
            self.completed.emit(str(path))
        except (OSError, ValueError) as exc:
            if path:
                path.unlink(missing_ok=True)
            self.error.emit(str(exc))


def apply_update(downloaded_file):
    # Never delete the working install. The verified portable executable can be
    # tested beside it; replacing a running install needs a signed installer.
    from PySide6.QtCore import QUrl
    from PySide6.QtGui import QDesktopServices

    QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(downloaded_file).parent)))
