"""Headless proxy and deterministic rule checks for CI."""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from desktop_sniffer.domain.rules.engine import RuleEngine
from desktop_sniffer.infrastructure.persistence.store import Store
from desktop_sniffer.services.openapi_tools import rules_from_openapi


def main():
    parser = argparse.ArgumentParser(prog="snare-cli")
    parser.add_argument("--workspace", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--host", default="127.0.0.1")
    match_command = sub.add_parser("match")
    match_command.add_argument("request", type=Path)
    export = sub.add_parser("export")
    export.add_argument("destination", type=Path)
    imports = sub.add_parser("import")
    imports.add_argument("source", type=Path)
    api = sub.add_parser("openapi")
    api.add_argument("source", type=Path)
    sub.add_parser("reset")
    args = parser.parse_args()
    store = Store(args.workspace)
    if args.command == "match":
        request = json.loads(args.request.read_text(encoding="utf-8"))
        request["body"] = json.dumps(request.get("body", {})).encode()
        engine = RuleEngine()
        engine.replace_rules(store.load_rules())
        selected = engine.select(
            request, {"local", "replace", "patch", "request_patch"}
        )
        print(
            json.dumps(
                {"match": selected.get("name") if selected else None},
                ensure_ascii=False,
            )
        )
        return 0 if selected else 2
    if args.command == "export":
        store.export_bundle(args.destination)
    elif args.command == "import":
        store.import_bundle(args.source)
    elif args.command == "openapi":
        store.save_rules(
            store.load_rules()
            + rules_from_openapi(json.loads(args.source.read_text(encoding="utf-8")))
        )
    elif args.command == "reset":
        import time
        from desktop_sniffer.infrastructure.persistence.atomic_json import atomic_json

        atomic_json(store.root / "reset.json", {"at": time.time()})
    elif args.command == "serve":
        import os
        from desktop_sniffer.services.engine_process import EngineProcess

        executable = EngineProcess.find_executable()
        if not executable:
            parser.error("mitmdump topilmadi")
        addon = (
            Path(__file__).parent / "infrastructure" / "mitmproxy" / "addon_entry.py"
        )
        environment = os.environ.copy()
        environment["SNIFFER_WORKSPACE"] = str(store.root.resolve())
        return subprocess.call(
            [
                executable,
                "--listen-host",
                args.host,
                "--listen-port",
                str(args.port),
                "--set",
                f"confdir={store.root.resolve() / 'mitmproxy'}",
                "-s",
                str(addon),
            ],
            env=environment,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
