import re
from pathlib import Path

from desktop_sniffer.infrastructure.persistence.store import Store


class WorkspaceService:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def open(self, name: str) -> Store:
        name = name.strip()

        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
            raise ValueError(
                "Workspace nomida 1–64 ta harf, raqam, _ yoki - ishlating."
            )

        reserved = {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10)),
        }

        if name.upper() in reserved:
            raise ValueError("Bu nom Windows tomonidan band qilingan")

        store = Store(self.root / name)
        store.load_rules()

        return store

    def names(self) -> list[str]:
        return sorted(
            path.name
            for path in self.root.iterdir()
            if path.is_dir()
        )