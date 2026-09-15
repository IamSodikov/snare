import json
import os
import shutil
import subprocess
import sys
import threading
import urllib.request
import zipfile
import ssl
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal

from desktop_sniffer import __version__

GITHUB_REPO = "IamSodikov/snare"

def get_ssl_context():
    try:
        return ssl.create_default_context()
    except Exception:
        return ssl._create_unverified_context()

class Updater(QObject):
    update_available = Signal(str, str, str)  # version, url, release_notes
    error = Signal(str)

    def check_for_updates(self):
        if not getattr(sys, "frozen", False):
            return

        def _check():
            try:
                url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
                req = urllib.request.Request(url, headers={"User-Agent": "Snare-Updater"})
                
                # SSL xatolarining oldini olish uchun
                ctx = get_ssl_context()
                try:
                    resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                except Exception:
                    ctx = ssl._create_unverified_context()
                    resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                
                with resp as response:
                    data = json.loads(response.read().decode())

                latest_version = data.get("tag_name", "")
                if latest_version and latest_version != __version__:
                    asset_url = None
                    if sys.platform == "win32":
                        target = "Snare-Windows.exe"
                    elif sys.platform == "darwin":
                        target = "Snare-MacOS.zip"
                    else:
                        target = "Snare-Linux"

                    for asset in data.get("assets", []):
                        if asset.get("name") == target:
                            asset_url = asset.get("browser_download_url")
                            break

                    if asset_url:
                        self.update_available.emit(
                            latest_version, asset_url, data.get("body", "")
                        )
            except Exception as exc:
                self.error.emit(f"Update check failed: {exc}")

        threading.Thread(target=_check, daemon=True).start()

class DownloadThread(QThread):
    progress = Signal(int)
    finished = Signal(str)
    error = Signal(str)

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        try:
            temp_dir = Path(os.getenv("TEMP", "/tmp"))
            if sys.platform == "darwin":
                filename = temp_dir / "Snare-MacOS.zip"
            elif sys.platform == "win32":
                filename = temp_dir / "Snare-update.exe"
            else:
                filename = temp_dir / "Snare-update"

            req = urllib.request.Request(self.url, headers={"User-Agent": "Snare-Updater"})
            
            ctx = get_ssl_context()
            try:
                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            except Exception:
                ctx = ssl._create_unverified_context()
                resp = urllib.request.urlopen(req, timeout=10, context=ctx)

            with resp as response, open(filename, "wb") as f:
                total_size = int(response.info().get("Content-Length", 0))
                downloaded = 0
                chunk_size = 8192
                while True:
                    buffer = response.read(chunk_size)
                    if not buffer:
                        break
                    f.write(buffer)
                    downloaded += len(buffer)
                    if total_size > 0:
                        self.progress.emit(int(downloaded * 100 / total_size))

            self.finished.emit(str(filename))
        except Exception as exc:
            self.error.emit(str(exc))

def apply_update(downloaded_file: str):
    if not getattr(sys, "frozen", False):
        return

    from PySide6.QtWidgets import QApplication
    current_exe = Path(sys.executable)
    downloaded = Path(downloaded_file)

    if sys.platform == "win32":
        bat_path = current_exe.parent / "update_snare.bat"
        with open(bat_path, "w") as f:
            f.write(
                f"""@echo off
set _MEIPASS2=
timeout /t 3 /nobreak > NUL
del "{current_exe}"
move /y "{downloaded}" "{current_exe}"
start "" "{current_exe}"
del "%~f0"
"""
            )
        env = os.environ.copy()
        env.pop("_MEIPASS2", None)
        env.pop("_MEIPASS", None)
        subprocess.Popen(
            str(bat_path), shell=True, creationflags=subprocess.CREATE_NO_WINDOW, env=env
        )
        QApplication.quit()
    elif sys.platform == "darwin":
        extract_dir = downloaded.parent / "snare_mac_update"
        extract_dir.mkdir(exist_ok=True)
        with zipfile.ZipFile(downloaded, "r") as zip_ref:
            zip_ref.extractall(extract_dir)

        new_app = extract_dir / "Snare.app"
        current_app = current_exe.parents[2]

        if current_app.suffix == ".app":
            sh_path = current_app.parent / "update_snare.sh"
            with open(sh_path, "w") as f:
                f.write(
                    f"""#!/bin/bash
unset _MEIPASS2
sleep 3
rm -rf "{current_app}"
mv "{new_app}" "{current_app}"
open "{current_app}"
rm -rf "{extract_dir}"
rm "{downloaded}"
rm "$0"
"""
                )
            os.chmod(sh_path, 0o755)
            env = os.environ.copy()
            env.pop("_MEIPASS2", None)
            env.pop("_MEIPASS", None)
            subprocess.Popen([str(sh_path)], start_new_session=True, env=env)
            QApplication.quit()
    else:
        sh_path = current_exe.parent / "update_snare.sh"
        with open(sh_path, "w") as f:
            f.write(
                f"""#!/bin/bash
unset _MEIPASS2
sleep 3
rm -f "{current_exe}"
mv "{downloaded}" "{current_exe}"
chmod +x "{current_exe}"
"{current_exe}" &
rm "$0"
"""
            )
        os.chmod(sh_path, 0o755)
        env = os.environ.copy()
        env.pop("_MEIPASS2", None)
        env.pop("_MEIPASS", None)
        subprocess.Popen([str(sh_path)], start_new_session=True, env=env)
        QApplication.quit()
