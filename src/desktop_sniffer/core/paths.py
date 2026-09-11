from pathlib import Path

from PySide6.QtCore import QStandardPaths


def application_data_dir() -> Path:
    location = QStandardPaths.writableLocation(
        QStandardPaths.StandardLocation.AppDataLocation
    )

    if not location:
        raise RuntimeError("Application data katalogi aniqlanmadi")

    directory = Path(location)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def workspaces_dir() -> Path:
    directory = application_data_dir() / "workspaces"
    directory.mkdir(parents=True, exist_ok=True)
    return directory