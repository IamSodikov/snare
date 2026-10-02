"""Run the packaged Qt UI and internal proxy twice, then exit with a CI status."""

import json
import socket
import tempfile
import threading
import time
from pathlib import Path
from urllib.request import ProxyHandler, Request, build_opener

from PySide6.QtCore import QObject, QTimer, Signal

from desktop_sniffer.domain.rules.defaults import default_rule
from desktop_sniffer.ui.windows.main_window import MainWindow


class Result(QObject):
    completed = Signal(bool, str)


def smoke_test(application):
    root = Path(tempfile.mkdtemp(prefix="snare-smoke-"))
    import desktop_sniffer.ui.windows.main_window as module

    module.workspaces_dir = lambda: root / "workspaces"
    module.application_data_dir = lambda: root
    window = MainWindow(autostart=False)
    window.show()
    window.system_proxy.setChecked(False)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    window.proxy_port.setValue(port)
    rule = default_rule()
    rule.update(host="snare.test", path="/smoke", body='{"smoke":true}')
    window.store.save_rules([rule])
    window.rules_page.refresh()
    ready_count = 0
    done = Result()
    finished = False
    engine_logs = []
    window.engine.log_received.connect(lambda text: engine_logs.append(text))

    def complete(ok, message):
        nonlocal finished
        if finished:
            return
        finished = True
        (Path.cwd() / "smoke-result.json").write_text(
            json.dumps(
                {
                    "ok": ok,
                    "message": message,
                    "ready_count": ready_count,
                    "style": application.style().objectName(),
                    "font": application.font().family(),
                    "engine_logs": engine_logs[-30:],
                }
            ),
            encoding="utf-8",
        )
        window.engine.stop(sync=True)
        window.captures_page.timer.stop()
        window.hide()
        application.exit(0 if ok else 1)

    done.completed.connect(complete)

    def request():
        try:
            proxy = f"http://127.0.0.1:{port}"
            opener = build_opener(ProxyHandler({"http": proxy}))
            req = Request("http://snare.test/smoke")
            req.set_proxy(f"127.0.0.1:{port}", "http")
            with opener.open(req, timeout=10) as response:
                if json.loads(response.read()) != {"smoke": True}:
                    raise ValueError("Wrong mock response")
            # Final response replaces its pending capture asynchronously.
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                documents = window.store.documents()
                if any(d.get("final") and not d.get("pending") for d in documents):
                    break
                time.sleep(0.05)
            else:
                raise ValueError("No completed capture")
            done.completed.emit(
                True, "UI + internal proxy restart + real local mock passed"
            )
        except Exception as exc:
            done.completed.emit(False, str(exc))

    def ready(*args):
        nonlocal ready_count
        ready_count += 1
        if ready_count == 1:
            QTimer.singleShot(100, window.restart_engine)
        elif ready_count == 2:
            # Wait past the old 3-second kill deadline before exercising the proxy.
            QTimer.singleShot(
                3500, lambda: threading.Thread(target=request, daemon=True).start()
            )

    window.engine.ready.connect(ready)
    window.engine.failed.connect(lambda msg: complete(False, msg))
    QTimer.singleShot(45000, lambda: complete(False, "Packaged smoke timeout"))
    QTimer.singleShot(0, window.restart_engine)
    return application.exec()
