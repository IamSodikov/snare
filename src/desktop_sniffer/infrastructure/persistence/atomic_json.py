import json
import os
import tempfile
from pathlib import Path


def atomic_json(path: Path, document):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    descriptor, temporary = tempfile.mkstemp(
        prefix=".write-",
        suffix=".json",
        dir=str(path.parent),
    )

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            json.dump(
                document,
                file,
                ensure_ascii=False,
                indent=2,
            )
            file.flush()
            os.fsync(file.fileno())

        os.replace(temporary, path)

    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)