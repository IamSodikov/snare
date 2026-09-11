import asyncio
import os

from mitmproxy import ctx, http

from desktop_sniffer.domain.rules.engine import RuleEngine
from desktop_sniffer.infrastructure.mitmproxy.capture_writer import CaptureWriter
from desktop_sniffer.infrastructure.mitmproxy.snapshots import (
    header_pairs,
    make_headers,
    request_snapshot,
    response_snapshot,
)
from desktop_sniffer.infrastructure.persistence.store import Store


class DesktopAddon:
    def __init__(self):
        self.store = Store(os.environ["SNIFFER_WORKSPACE"])
        self.engine = RuleEngine()
        self.version = None
        self.capture_writer = CaptureWriter(self.store)

    def running(self):
        self.capture_writer.start()
        self.reload_rules()

    def done(self):
        self.capture_writer.stop()

    def reload_rules(self):
        for error in self.capture_writer.pop_errors():
            ctx.log.error(f"Capture storage: {error}")

        try:
            stat = self.store.rules_path.stat()
            version = (stat.st_mtime_ns, stat.st_size)

            if version == self.version:
                return

            # Invalid konfiguratsiyada oldingi qoidalar saqlanadi.
            self.version = version
            rules = self.store.load_rules()
            self.engine.replace_rules(rules)

            ctx.log.info(
                f"Desktop rules loaded: {len(rules)}; scenarios reset"
            )

        except Exception as exc:
            ctx.log.error(f"Rules reload failed: {exc}")

    @staticmethod
    def request_data(flow):
        return {
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": header_pairs(flow.request.headers),
            "body": flow.request.get_content(strict=False) or b"",
        }

    async def apply(self, flow, rule):
        patch = rule["action"] == "patch"
        preserve_body = patch and rule.get("preserve_body", False)

        body = b""

        if not preserve_body:
            if rule.get("fixture"):
                body = await asyncio.to_thread(
                    self.store.fixture,
                    rule["fixture"],
                )
            else:
                body = rule.get("body", "").encode("utf-8")

        if patch:
            if flow.response is None:
                return

            response = flow.response.copy()

            if rule.get("status"):
                response.status_code = rule["status"]

            if not preserve_body:
                response.headers.pop("content-encoding", None)
                response.raw_content = body

            replacement_names = {
                name.lower()
                for name, _ in rule.get("headers", [])
            }

            for name in replacement_names:
                response.headers.pop(name, None)

            for name, value in rule.get("headers", []):
                response.headers.add(name, value)

        else:
            response = http.Response.make(
                rule.get("status", 200),
                body,
                make_headers(rule.get("headers", [])),
            )

        for name in rule.get("remove_headers", []):
            response.headers.pop(name, None)

        if (
            flow.request.method == "HEAD"
            or response.status_code in (204, 205, 304)
        ):
            response.raw_content = b""
            response.headers.pop("transfer-encoding", None)

            if response.status_code in (204, 304):
                response.headers.pop("content-length", None)
            else:
                response.headers["content-length"] = "0"

        elif not preserve_body:
            response.headers.pop("transfer-encoding", None)
            response.headers["content-length"] = str(
                len(response.raw_content or b"")
            )

        delay_ms = rule.get("delay_ms", 0)

        if delay_ms:
            await asyncio.sleep(delay_ms / 1000)

        flow.response = response
        flow.metadata["desktop_mock_id"] = rule["id"]
        flow.metadata["desktop_mock_action"] = rule["action"]

        label = f"Mock: {rule.get('name', rule['id'])}"
        flow.comment = (
            f"{flow.comment} | {label}" if flow.comment else label
        )

    async def apply_request_patch(self, flow, rule):
        preserve_body = rule.get("preserve_body", False)

        if rule.get("rewrite_method"):
            flow.request.method = rule["rewrite_method"]

        if rule.get("rewrite_url"):
            flow.request.url = rule["rewrite_url"]

        if not preserve_body:
            if rule.get("fixture"):
                body = await asyncio.to_thread(
                    self.store.fixture,
                    rule["fixture"],
                )
            else:
                body = rule.get("body", "").encode("utf-8")

            flow.request.headers.pop("content-encoding", None)
            flow.request.raw_content = body

        replacement_names = {
            name.lower()
            for name, _ in rule.get("headers", [])
        }

        for name in replacement_names:
            flow.request.headers.pop(name, None)

        for name, value in rule.get("headers", []):
            flow.request.headers.add(name, value)

        for name in rule.get("remove_headers", []):
            flow.request.headers.pop(name, None)

        if not preserve_body:
            flow.request.headers.pop("transfer-encoding", None)
            flow.request.headers["content-length"] = str(
                len(flow.request.raw_content or b"")
            )

        delay_ms = rule.get("delay_ms", 0)

        if delay_ms:
            await asyncio.sleep(delay_ms / 1000)

        flow.metadata["desktop_mock_id"] = rule["id"]
        flow.metadata["desktop_mock_action"] = rule["action"]

        label = f"Request patch: {rule.get('name', rule['id'])}"
        flow.comment = (
            f"{flow.comment} | {label}" if flow.comment else label
        )

    def capture(self, flow, original):
        document = {
            "id": flow.id,
            "created": flow.request.timestamp_start,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "request_headers": header_pairs(flow.request.headers),
            "request": request_snapshot(flow.request),
            "original": original,
            "final": response_snapshot(flow.response),
            "mock_rule_id": flow.metadata.get("desktop_mock_id"),
            "mock_action": flow.metadata.get("desktop_mock_action"),
            "error": str(flow.error) if flow.error else None,
        }

        if not self.capture_writer.submit(document):
            ctx.log.warn(
                "Native capture skipped: queue full or writer stopped. "
                "Original mitmweb flow is unaffected."
            )

    async def request(self, flow: http.HTTPFlow):
        self.reload_rules()

        # Replay qilingan flow eski mock marker'larini saqlamasin.
        flow.metadata.pop("desktop_mock_id", None)
        flow.metadata.pop("desktop_mock_action", None)

        try:
            rule = self.engine.select(
                self.request_data(flow),
                {"local", "request_patch"},
            )

            if rule:
                if rule["action"] == "request_patch":
                    await self.apply_request_patch(flow, rule)
                else:
                    await self.apply(flow, rule)

        except Exception as exc:
            ctx.log.error(f"Local mock failed: {exc}")

    async def response(self, flow: http.HTTPFlow):
        self.reload_rules()

        is_local = (
            flow.metadata.get("desktop_mock_action") == "local"
        )

        original = (
            None if is_local else response_snapshot(flow.response)
        )

        try:
            if not is_local:
                rule = self.engine.select(
                    self.request_data(flow),
                    {"replace", "patch"},
                )

                if rule:
                    await self.apply(flow, rule)

        except Exception as exc:
            ctx.log.error(f"Response mock failed: {exc}")

        self.capture(flow, original)

    def error(self, flow: http.HTTPFlow):
        self.capture(flow, None)
