import base64
import json


def snapshot_text(snapshot) -> str:
    if snapshot is None:
        return "Response mavjud emas."

    raw = base64.b64decode(snapshot["body_b64"])

    try:
        body = raw.decode("utf-8")

        try:
            body = json.dumps(
                json.loads(body),
                ensure_ascii=False,
                indent=2,
            )
        except ValueError:
            pass

    except UnicodeDecodeError:
        body = (
            f"<binary: {len(raw)} captured bytes>\n\n"
            f"Hex preview:\n{raw[:512].hex(' ')}"
        )

    headers = "\n".join(
        f"{name}: {value}"
        for name, value in snapshot["headers"]
    )

    truncated = (
        "\n\n[TRUNCATED: body to‘liq saqlanmagan]"
        if snapshot.get("truncated")
        else ""
    )

    return (
        f"Status: {snapshot['status']}\n"
        f"Body size: {snapshot['body_size']} bytes\n"
        f"{headers}\n\n"
        f"{body}{truncated}"
    )