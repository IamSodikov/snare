import base64
import copy
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from desktop_sniffer.core.constants import (
    CAPTURE_DISPLAY_LIMIT,
    CAPTURE_RETENTION,
    MAX_BUNDLE_SIZE,
    MAX_FIXTURE_SIZE,
)
from desktop_sniffer.domain.rules.validation import validate_rules
from desktop_sniffer.infrastructure.persistence.atomic_json import atomic_json


class Store:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

        self.rules_path = self.root / "rules.json"
        self.db_path = self.root / "traffic.sqlite3"

        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS fixtures (
                    id TEXT PRIMARY KEY,
                    body BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS captures (
                    id TEXT PRIMARY KEY,
                    created REAL NOT NULL,
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    status INTEGER,
                    document TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS captures_created
                ON captures(created DESC);
            """)
            try:
                db.execute("ALTER TABLE captures ADD COLUMN mock_action TEXT;")
            except sqlite3.OperationalError:
                pass
            try:
                db.execute("ALTER TABLE captures ADD COLUMN rpc_method TEXT;")
            except sqlite3.OperationalError:
                pass


        if not self.rules_path.exists():
            self.save_rules([])

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.db_path, timeout=10)

        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def load_rules(self) -> list:
        document = json.loads(
            self.rules_path.read_text(encoding="utf-8")
        )

        if not isinstance(document, dict) or document.get("version") != 1:
            raise ValueError("Unsupported rules format")

        rules = document.get("rules")
        validate_rules(rules)
        return rules

    def save_rules(self, rules):
        validate_rules(rules)

        atomic_json(self.rules_path, {
            "version": 1,
            "rules": rules,
        })

    def put_fixture(self, body: bytes) -> str:
        if len(body) > MAX_FIXTURE_SIZE:
            raise ValueError("Fixture exceeds 32 MiB")

        fixture_id = str(uuid.uuid4())

        with self.connect() as db:
            db.execute(
                "INSERT INTO fixtures(id, body) VALUES (?, ?)",
                (fixture_id, body),
            )

        return fixture_id

    def fixture(self, fixture_id: str) -> bytes:
        with self.connect() as db:
            row = db.execute(
                "SELECT body FROM fixtures WHERE id = ?",
                (fixture_id,),
            ).fetchone()

        if row is None:
            raise ValueError(f"Fixture topilmadi: {fixture_id}")

        return bytes(row[0])

    def save_capture(self, document: dict):
        response = document.get("final")
        status = response["status"] if response else None

        display_url = document["url"]
        rpc_method = None
        if "rpc" in display_url.lower() or "graphql" in display_url.lower():
            req = document.get("request")
            if req and req.get("body_b64"):
                try:
                    raw = base64.b64decode(req["body_b64"]).decode("utf-8")
                    body = json.loads(raw)
                    extracted = []
                    if isinstance(body, dict):
                        for key in ["method", "methods", "action", "operationName"]:
                            if key in body:
                                val = body[key]
                                if isinstance(val, str):
                                    extracted.append(val)
                                elif isinstance(val, list) and all(isinstance(x, str) for x in val):
                                    extracted.extend(val)
                    elif isinstance(body, list):
                        for item in body:
                            if isinstance(item, dict):
                                for key in ["method", "action"]:
                                    if key in item and isinstance(item[key], str):
                                        extracted.append(item[key])
                    if extracted:
                        rpc_method = ", ".join(extracted)
                except Exception:
                    pass

        with self.connect() as db:
            db.execute("""
                INSERT OR REPLACE INTO captures
                (id, created, method, url, status, mock_action, rpc_method, document)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                document["id"],
                document.get("created") or time.time(),
                document["method"],
                display_url,
                status,
                document.get("mock_action"),
                rpc_method,
                json.dumps(document, ensure_ascii=False),
            ))

            # We probabilistically or efficiently prune old records
            db.execute("""
                DELETE FROM captures
                WHERE created < (
                    SELECT created FROM captures
                    ORDER BY created DESC
                    LIMIT 1 OFFSET ?
                )
            """, (CAPTURE_RETENTION,))

    def list_captures(self, query="", limit=CAPTURE_DISPLAY_LIMIT):
        with self.connect() as db:
            if not query:
                return db.execute("""
                    SELECT id, method, url, status, mock_action, rpc_method
                    FROM captures
                    ORDER BY created DESC
                    LIMIT ?
                """, (limit,)).fetchall()
            else:
                like_query = f"%{query}%"
                return db.execute("""
                    SELECT id, method, url, status, mock_action, rpc_method
                    FROM captures
                    WHERE url LIKE ? OR method LIKE ? OR status LIKE ? OR mock_action LIKE ? OR rpc_method LIKE ?
                    ORDER BY created DESC
                    LIMIT ?
                """, (like_query, like_query, like_query, like_query, like_query, limit)).fetchall()

    def capture(self, flow_id: str):
        with self.connect() as db:
            row = db.execute(
                "SELECT document FROM captures WHERE id = ?",
                (flow_id,),
            ).fetchone()

        return json.loads(row[0]) if row else None

    def clear_captures(self):
        with self.connect() as db:
            db.execute("DELETE FROM captures")

    def export_bundle(self, destination):
        rules = self.load_rules()

        fixture_ids = {
            rule["fixture"]
            for rule in rules
            if rule.get("fixture")
        }

        document = {
            "version": 1,
            "rules": rules,
            "fixtures": {
                fixture_id: base64.b64encode(
                    self.fixture(fixture_id)
                ).decode("ascii")
                for fixture_id in fixture_ids
            },
        }

        serialized = json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")

        if len(serialized) > MAX_BUNDLE_SIZE:
            raise ValueError("Bundle exceeds 64 MiB")

        atomic_json(Path(destination), document)

    def import_bundle(self, source):
        source = Path(source)

        if source.stat().st_size > MAX_BUNDLE_SIZE:
            raise ValueError("Bundle exceeds 64 MiB")

        document = json.loads(source.read_text(encoding="utf-8"))

        if not isinstance(document, dict) or document.get("version") != 1:
            raise ValueError("Unsupported bundle format")

        rules = copy.deepcopy(document.get("rules"))
        validate_rules(rules)

        encoded = document.get("fixtures", {})

        if not isinstance(encoded, dict):
            raise ValueError("Invalid fixtures")

        fixtures = {}

        for key, value in encoded.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError("Invalid fixture entry")

            body = base64.b64decode(value, validate=True)

            if len(body) > MAX_FIXTURE_SIZE:
                raise ValueError("Fixture exceeds 32 MiB")

            fixtures[key] = body

        for rule in rules:
            fixture_id = rule.get("fixture")

            if fixture_id and fixture_id not in fixtures:
                raise ValueError(f"Missing fixture: {fixture_id}")

        mapping = {
            old_id: str(uuid.uuid4())
            for old_id in fixtures
        }

        with self.connect() as db:
            for old_id, body in fixtures.items():
                db.execute(
                    "INSERT INTO fixtures(id, body) VALUES (?, ?)",
                    (mapping[old_id], body),
                )

        for rule in rules:
            rule["id"] = str(uuid.uuid4())

            if rule.get("fixture"):
                rule["fixture"] = mapping[rule["fixture"]]

        self.save_rules(rules)