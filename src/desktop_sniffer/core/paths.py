from pathlib import Path
from PySide6.QtCore import QStandardPaths


def application_data_dir() -> Path:
    location = QStandardPaths.writableLocation(
        QStandardPaths.StandardLocation.AppDataLocation
    )
    if not location:
        raise RuntimeError("Application data katalogi aniqlanmadi")
    directory = Path(location)
    generic = Path(
        QStandardPaths.writableLocation(
            QStandardPaths.StandardLocation.GenericDataLocation
        )
    )
    # Older packaged releases did not set an organization name. Preserve their
    # Roaming/Snare workspace on Windows as well as GenericDataLocation installs.
    roots = [generic, directory.parent, directory.parent.parent]
    for root in roots:
        for relative in ("Snare", "DesktopSniffer", "LocalTools/DesktopSniffer"):
            legacy = root / relative
            if (legacy / "workspaces").exists():
                return legacy
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def workspaces_dir() -> Path:
    directory = application_data_dir() / "workspaces"
    directory.mkdir(parents=True, exist_ok=True)
    return directory
