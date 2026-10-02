import faulthandler
import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def configure_frozen_logging():
    """Keep diagnostics available in PyInstaller's windowed executables."""
    if not getattr(sys, "frozen", False):
        return None

    if len(sys.argv) > 1 and sys.argv[1] == "--mitmdump-internal":
        return None

    root = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "Snare" / "logs"
    root.mkdir(parents=True, exist_ok=True)
    path = root / "startup.log"
    stream = path.open("a", encoding="utf-8", buffering=1)
    # --windowed sets these to None on Windows; preserve startup diagnostics.
    if sys.stdout is None:
        sys.stdout = stream
    if sys.stderr is None:
        sys.stderr = stream
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler(stream)],
        force=True,
    )
    faulthandler.enable(file=stream)
    faulthandler.dump_traceback_later(30, file=stream)
    logger.info("Starting Snare (pid=%s)", os.getpid())
    return path



def restore_engine_streams():
    """Use an explicit log channel for the frozen GUI application's proxy child."""
    import os

    log_path = os.environ.get("SNIFFER_ENGINE_LOG")
    if log_path:
        stream = open(log_path, "a", encoding="utf-8", buffering=1)
        sys.stdout = sys.stderr = stream
        sys.__stdout__ = sys.__stderr__ = stream
        sys.stdin = open(os.devnull, "r", encoding="utf-8")



def main() -> int:
    """Create and run the desktop application."""
    log_path = configure_frozen_logging()
    try:
        return run_application()
    except Exception:
        logger.exception("Snare startup failed")
        if sys.platform == "win32" and log_path:
            import ctypes

            ctypes.windll.user32.MessageBoxW(
                None,
                f"Snare ishga tushmadi. Xato tafsilotlari:\n{log_path}",
                "Snare startup error",
                0x10,
            )
        raise
    finally:
        if log_path:
            faulthandler.cancel_dump_traceback_later()


def run_application() -> int:
    """Create and run the desktop application."""
    if len(sys.argv) > 1 and sys.argv[1] == "--mitmdump-internal":
        restore_engine_streams()
        try:
            from mitmproxy.tools.main import mitmdump

            sys.argv = [sys.argv[0]] + sys.argv[2:]
            return mitmdump()
        except Exception:
            import traceback

            traceback.print_exc()
            return 1

    import ctypes

    logger.info("Importing Qt")
    from PySide6.QtCore import QLockFile
    from PySide6.QtWidgets import QApplication, QMessageBox

    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "iamsodikov.snare.desktopsniffer.1.0"
        )
    except AttributeError:
        pass
    application = QApplication.instance() or QApplication(sys.argv)
    application.setApplicationName("Snare")
    application.setOrganizationName("LocalTools")
    from desktop_sniffer.ui.theme import apply_theme

    logger.info("Applying theme")
    apply_theme(application)
    if "--smoke-test" in sys.argv:
        from desktop_sniffer.smoke import smoke_test

        return smoke_test(application)
    from desktop_sniffer.core.paths import application_data_dir

    lock = QLockFile(str(application_data_dir() / "snare.lock"))
    logger.info("Checking single-instance lock")
    if not lock.tryLock(100):
        QMessageBox.information(None, "Snare", "Snare allaqachon ishga tushgan")
        return 1

    from desktop_sniffer.ui.windows.main_window import MainWindow

    logger.info("Creating main window and loading workspace")
    window = MainWindow()
    window.show()
    logger.info("Main window shown; starting event loop")
    if getattr(sys, "frozen", False):
        faulthandler.cancel_dump_traceback_later()
    return application.exec()


if __name__ == "__main__":
    import multiprocessing

    multiprocessing.freeze_support()
    sys.exit(main())
