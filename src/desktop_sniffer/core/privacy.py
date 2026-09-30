"""Sanitize saved or shared copies without changing live HTTP requests."""

import base64
import copy
import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SECRET_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
}
SECRET_FIELDS = {
    "password",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "api_key",
}


def redact_json(value):
    if isinstance(value, dict):
        return {
            key: "<redacted>" if key.lower() in SECRET_FIELDS else redact_json(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    return value


def redact_document(document):
    result = copy.deepcopy(document)
    parsed = urlsplit(result.get("url", ""))
    query = [
        (key, "<redacted>" if key.lower() in SECRET_FIELDS else value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    result["url"] = urlunsplit(
        parsed._replace(query=urlencode(query), netloc=parsed.netloc.split("@")[-1])
    )
    for name in ("request_original", "request", "original", "final"):
        snapshot = result.get(name)
        if not snapshot:
            continue
        if "url" in snapshot:
            sp = urlsplit(snapshot["url"])
            sq = [
                (k, "<redacted>" if k.lower() in SECRET_FIELDS else v)
                for k, v in parse_qsl(sp.query, keep_blank_values=True)
            ]
            snapshot["url"] = urlunsplit(
                sp._replace(query=urlencode(sq), netloc=sp.netloc.split("@")[-1])
            )
        snapshot["headers"] = [
            [key, "<redacted>" if key.lower() in SECRET_HEADERS else value]
            for key, value in snapshot.get("headers", [])
        ]
        try:
            value = json.loads(base64.b64decode(snapshot.get("body_b64", "")))
            raw = json.dumps(redact_json(value), ensure_ascii=False).encode()
            snapshot["body_b64"] = base64.b64encode(raw).decode()
            snapshot["body_size"] = len(raw)
        except (ValueError, UnicodeError):
            pass
    result["request_headers"] = result.get("request", {}).get("headers", [])
    result["redacted"] = True
    return result
