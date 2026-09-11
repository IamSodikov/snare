import secrets
import shutil
import socket
import sys
import time
from pathlib import Path

from PySide6.QtCore import (
    QObject,
    QProcess,
    QProcessEnvironment,
    QTimer,
    Signal,
)

from desktop_sniffer.core.constants import (
    ENGINE_STARTUP_TIMEOUT_SECONDS,
)


def free_port() -> int:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        return server.getsockname()[1]


class EngineProcess(QObject):
    log_received = Signal(str)
    status_changed = Signal(str)
    password_changed = Signal(str)
    ready = Signal(str)
    failed = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

        self._process = QProcess(self)
        self._process.setProcessChannelMode(
            QProcess.ProcessChannelMode.MergedChannels
        )

        self._process.readyReadStandardOutput.connect(self._read_logs)
        self._process.errorOccurred.connect(self._on_error)
        self._process.finished.connect(self._on_finished)

        self._poll = QTimer(self)
        self._poll.setInterval(300)
        self._poll.timeout.connect(self._check_ready)

        self._stopping = False
        self._password = ""
        self._proxy_port = None
        self._deadline = 0.0

    @staticmethod
    def find_executable():
        name = "mitmdump.exe" if sys.platform == "win32" else "mitmdump"

        if getattr(sys, 'frozen', False):
            if hasattr(sys, '_MEIPASS'):
                bundled = Path(sys._MEIPASS) / name
                if bundled.exists():
                    return str(bundled)
            
            # fallback for --onedir builds where sys.executable is in the same folder
            local_bundle = Path(sys.executable).resolve().parent / name
            if local_bundle.exists():
                return str(local_bundle)
                
            # fallback for macOS .app bundles where mitmproxy might be an embedded .app
            if sys.platform == "darwin":
                # Check next to executable
                macos_app_bundle = Path(sys.executable).resolve().parent / "mitmproxy.app" / "Contents" / "MacOS" / "mitmdump"
                if macos_app_bundle.exists():
                    return str(macos_app_bundle)
                
                # Check in Resources directory
                macos_app_bundle_res = Path(sys.executable).resolve().parent.parent / "Resources" / "mitmproxy.app" / "Contents" / "MacOS" / "mitmdump"
                if macos_app_bundle_res.exists():
                    return str(macos_app_bundle_res)

        local = Path(sys.executable).resolve().parent / name

        if local.exists():
            return str(local)

        return shutil.which("mitmdump")

    def start(
        self,
        workspace: Path,
        proxy_port: int,
        listen_host: str = "127.0.0.1",
    ):
        self.status_changed.emit("Engine ishga tushirilmoqda…")
        
        if self._process.state() != QProcess.ProcessState.NotRunning:
            # Store arguments for a deferred start and stop the current one
            self._deferred_start_args = (workspace, proxy_port, listen_host)
            self.stop()
            return

        self._start_internal(workspace, proxy_port, listen_host)

    def _start_internal(self, workspace: Path, proxy_port: int, listen_host: str):
        executable = self.find_executable()

        if not executable:
            self.failed.emit(
                "mitmdump topilmadi. "
                "Loyihani virtual environment ichiga install qiling."
            )
            return

        package_root = Path(__file__).resolve().parents[1]
        addon_entry = (
            package_root
            / "infrastructure"
            / "mitmproxy"
            / "addon_entry.py"
        )

        if not addon_entry.is_file():
            self.failed.emit(f"Addon topilmadi: {addon_entry}")
            return

        self._proxy_port = proxy_port
        self._password = secrets.token_hex(16)
        self.password_changed.emit(self._password)

        environment = QProcessEnvironment.systemEnvironment()
        environment.insert("SNIFFER_WORKSPACE", str(workspace))
        environment.insert("PYTHONUNBUFFERED", "1")

        self._process.setProcessEnvironment(environment)
        self._process.setWorkingDirectory(str(workspace))

        self._deadline = (
            time.monotonic() + ENGINE_STARTUP_TIMEOUT_SECONDS
        )

        self.status_changed.emit("Engine ishga tushirilmoqda…")

        self._process.start(executable, [
            "--listen-host", listen_host,
            "--listen-port", str(proxy_port),
            "-s", str(addon_entry),
        ])

        self._poll.start()

    def stop(self, sync=False):
        self._stopping = True
        self._poll.stop()

        if self._process.state() != QProcess.ProcessState.NotRunning:
            self._process.terminate()
            if sync:
                if not self._process.waitForFinished(3000):
                    self._process.kill()
                    self._process.waitForFinished(1500)
            else:
                # Asynchronous kill fallback
                QTimer.singleShot(3000, self._ensure_killed)
        else:
            self._stopping = False
            self.status_changed.emit("Engine to‘xtatilgan")

    def _ensure_killed(self):
        if self._process.state() != QProcess.ProcessState.NotRunning:
            self._process.kill()

    def is_running(self) -> bool:
        return self._process.state() == QProcess.ProcessState.Running

    def _read_logs(self):
        text = bytes(
            self._process.readAllStandardOutput()
        ).decode("utf-8", errors="replace")

        if self._password:
            text = text.replace(self._password, "<redacted>")

        if text.strip():
            self.log_received.emit(text.rstrip())

    def _on_error(self, *_):
        self._poll.stop()

        if not self._stopping:
            self.failed.emit(self._process.errorString())

    def _on_finished(self, code, *_):
        self._poll.stop()

        # Call deferred start if exists
        deferred = getattr(self, "_deferred_start_args", None)
        if deferred:
            self._deferred_start_args = None
            self._stopping = False
            self._start_internal(*deferred)
            return

        if not self._stopping:
            self.status_changed.emit(
                f"Engine to‘xtadi: {code}. Engine Logs’ni tekshiring."
            )
        else:
            self.status_changed.emit("Engine to‘xtatilgan")

        self._stopping = False

    def _check_ready(self):
        if time.monotonic() > self._deadline:
            self.stop()
            self.failed.emit(
                "Engine startup timeout. Engine Logs’ni tekshiring."
            )
            return

        if self._process.state() != QProcess.ProcessState.Running:
            return

        try:
            with socket.create_connection(
                ("127.0.0.1", self._proxy_port),
                timeout=0.05,
            ):
                pass
        except OSError:
            return

        self._poll.stop()

        self.ready.emit("")
        self.status_changed.emit(
            f"Proxy: 127.0.0.1:{self._proxy_port}"
        )
