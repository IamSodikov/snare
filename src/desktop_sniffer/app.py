import sys


def main() -> int:
    """Create and run the desktop application."""
    if len(sys.argv) > 1 and sys.argv[1] == "--mitmdump-internal":
        from mitmproxy.tools.main import mitmdump
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        return mitmdump()

    import ctypes

    from PySide6.QtWidgets import QApplication
    try:
        myappid = 'iamsodikov.snare.desktopsniffer.1.0'
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    except Exception:
        pass
        
    application = QApplication.instance() or QApplication(sys.argv)
    
    from desktop_sniffer.ui.windows.main_window import MainWindow
    window = MainWindow()
    window.show()
    return application.exec()

if __name__ == '__main__':
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
