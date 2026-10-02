"""Portable replay commands and standard HAR exchange."""

import base64
import json
import shlex
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlsplit

from desktop_sniffer.core.privacy import redact_document
from desktop_sniffer.infrastructure.persistence.atomic_json import atomic_json


def curl_command(document):
    request = document.get("request_original") or document.get("request") or {}
    if request.get("truncated"):
        raise ValueError("Request body kesilgan; to‘liq cURL yaratib bo‘lmaydi")
    args = [
        "curl",
        "--request",
        request.get("method", document["method"]),
        request.get("url", document["url"]),
    ]
    for key, value in request.get("headers", []):
        if key.lower() not in ("host", "content-length", "transfer-encoding"):
            args.extend(["--header", f"{key}: {value}"])
    raw = base64.b64decode(request.get("body_b64", ""))
    if raw:
        try:
            body = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(
                "Binary body uchun fixture eksportidan foydalaning"
            ) from exc
        if "\x00" in body:
            raise ValueError("Binary body cURL text sifatida chiqarilmaydi")
        args.extend(["--data-raw", body])
    return shlex.join(args)


def export_har(store, path, sanitize=True):
    entries = []
    for original in reversed(store.documents()):
        doc = redact_document(original) if sanitize else original
        req = doc.get("request_original") or doc.get("request") or {}
        res = doc.get("final") or {}
        url = req.get("url", doc["url"])
        # Preserve sanitized URL even when original request contains an embedded URL.
        if sanitize:
            url = doc["url"]
        entries.append(
            {
                "startedDateTime": datetime.fromtimestamp(
                    doc.get("created", time.time()), timezone.utc
                ).isoformat(),
                "time": doc.get("duration_ms", 0),
                "request": {
                    "method": req.get("method", doc["method"]),
                    "url": url,
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": k, "value": v} for k, v in req.get("headers", [])
                    ],
                    "queryString": [
                        {"name": k, "value": v}
                        for k, v in parse_qsl(urlsplit(url).query)
                    ],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": req.get("body_size", 0),
                    "postData": {
                        "mimeType": "application/octet-stream",
                        "text": req.get("body_b64", ""),
                        "encoding": "base64",
                    },
                },
                "response": {
                    "status": res.get("status", 0),
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": k, "value": v} for k, v in res.get("headers", [])
                    ],
                    "cookies": [],
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": res.get("body_size", 0),
                    "content": {
                        "size": res.get("body_size", 0),
                        "mimeType": "application/octet-stream",
                        "text": res.get("body_b64", ""),
                        "encoding": "base64",
                    },
                },
                "cache": {},
                "timings": {"send": 0, "wait": doc.get("duration_ms", 0), "receive": 0},
                "_snare": {
                    "requestTruncated": req.get("truncated", False),
                    "responseTruncated": res.get("truncated", False),
                },
            }
        )
    atomic_json(
        path,
        {
            "log": {
                "version": "1.2",
                "creator": {"name": "Snare", "version": "1.2"},
                "entries": entries,
            }
        },
    )


def import_har(store, path):
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("HAR hajmi 64 MiB’dan katta")
    entries = json.loads(path.read_text(encoding="utf-8"))["log"]["entries"]
    documents = []
    for entry in entries[:1000]:
        request = entry["request"]
        response = entry["response"]

        def snapshot(data, content):
            text = content.get("text", "")
            raw = (
                base64.b64decode(text, validate=True)
                if content.get("encoding") == "base64"
                else text.encode()
            )
            return {
                "headers": [[h["name"], h["value"]] for h in data.get("headers", [])],
                "body_b64": base64.b64encode(raw[: 2 * 1024 * 1024]).decode(),
                "body_size": len(raw),
                "truncated": len(raw) > 2 * 1024 * 1024,
            }

        req = snapshot(request, request.get("postData", {}))
        res = snapshot(response, response.get("content", {}))
        res["status"] = response.get("status", 0)
        flags = entry.get("_snare", {})
        req["truncated"] |= bool(flags.get("requestTruncated"))
        res["truncated"] |= bool(flags.get("responseTruncated"))
        documents.append(
            {
                "id": str(uuid.uuid4()),
                "created": time.time(),
                "method": request["method"],
                "url": request["url"],
                "request": req,
                "final": res,
                "duration_ms": entry.get("time", 0),
            }
        )
    for document in documents:
        store.save_capture(document)
    return len(documents)
