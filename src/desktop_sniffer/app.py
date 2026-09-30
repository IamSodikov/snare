import sys


def restore_engine_streams():
    """Reconnect inherited QProcess pipes in a Windows windowed executable."""
    if sys.platform != "win32":
        return
    import ctypes
    import io
    import msvcrt
    import os

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetStdHandle.argtypes = [ctypes.c_ulong]
    kernel.GetStdHandle.restype = ctypes.c_void_p
    for name, handle_number in (("stdout", -11), ("stderr", -12)):
        if getattr(sys, name) is not None:
            continue
        handle = kernel.GetStdHandle(handle_number & 0xFFFFFFFF)
        if handle and handle != ctypes.c_void_p(-1).value:
            fd = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
            stream = io.TextIOWrapper(
                os.fdopen(fd, "wb", buffering=0), encoding="utf-8", write_through=True
            )
        else:
            stream = open(os.devnull, "w", encoding="utf-8")
        setattr(sys, name, stream)
        setattr(sys, f"__{name}__", stream)
    if sys.stdin is None:
        sys.stdin = open(os.devnull, "r", encoding="utf-8")


def main() -> int:
    """Create and run the desktop application."""
    if len(sys.argv) > 1 and sys.argv[1] == "--mitmdump-internal":
        restore_engine_streams()
        from mitmproxy.tools.main import mitmdump

        sys.argv = [sys.argv[0]] + sys.argv[2:]
        return mitmdump()

    import ctypes

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

    apply_theme(application)
    if "--smoke-test" in sys.argv:
        from desktop_sniffer.smoke import smoke_test

        return smoke_test(application)
    from desktop_sniffer.core.paths import application_data_dir

    lock = QLockFile(str(application_data_dir() / "snare.lock"))
    if not lock.tryLock(100):
        QMessageBox.information(None, "Snare", "Snare allaqachon ishga tushgan")
        return 1

    from desktop_sniffer.ui.windows.main_window import MainWindow

    window = MainWindow()
    window.show()
    return application.exec()


if __name__ == "__main__":
    import multiprocessing

    multiprocessing.freeze_support()
    sys.exit(main())
