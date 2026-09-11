import base64

from mitmproxy import http

from desktop_sniffer.core.constants import MAX_CAPTURE_BODY


def header_pairs(headers) -> list:
    return [
        [
            name.decode("latin-1"),
            value.decode("latin-1"),
        ]
        for name, value in headers.fields
    ]


def make_headers(pairs):
    return http.Headers([
        (
            name.encode("ascii"),
            value.encode("latin-1"),
        )
        for name, value in pairs
    ])


def response_snapshot(response):
    if response is None:
        return None

    headers = response.headers.copy()

    try:
        body = response.get_content(strict=True) or b""
        headers.pop("content-encoding", None)
        headers.pop("content-length", None)
        headers.pop("transfer-encoding", None)

    except ValueError:
        # Decode qilib bo'lmasa raw entity body saqlanadi.
        body = response.raw_content or b""
        headers.pop("transfer-encoding", None)

    return {
        "status": response.status_code,
        "headers": header_pairs(headers),
        "body_b64": base64.b64encode(
            body[:MAX_CAPTURE_BODY]
        ).decode("ascii"),
        "body_size": len(body),
        "truncated": len(body) > MAX_CAPTURE_BODY,
    }


def request_snapshot(request):
    headers = request.headers.copy()

    try:
        body = request.get_content(strict=True) or b""
        headers.pop("content-encoding", None)
        headers.pop("content-length", None)
        headers.pop("transfer-encoding", None)

    except ValueError:
        body = request.raw_content or b""
        headers.pop("transfer-encoding", None)

    return {
        "headers": header_pairs(headers),
        "body_b64": base64.b64encode(
            body[:MAX_CAPTURE_BODY]
        ).decode("ascii"),
        "body_size": len(body),
        "truncated": len(body) > MAX_CAPTURE_BODY,
    }
