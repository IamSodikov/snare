import sys


def main() -> int:
    """Create and run the desktop application."""
    if len(sys.argv) > 1 and sys.argv[1] == "--mitmdump-internal":
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
