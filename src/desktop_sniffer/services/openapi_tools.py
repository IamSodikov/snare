"""Import local OpenAPI JSON examples as explicitly disabled mock rules."""

import json
import re

from desktop_sniffer.domain.rules.defaults import default_rule


def rules_from_openapi(document):
    if not isinstance(document.get("paths"), dict):
        raise ValueError("OpenAPI paths topilmadi; JSON formatidan foydalaning")
    rules = []
    for path, methods in document["paths"].items():
        for method, operation in methods.items():
            if method.lower() not in (
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "head",
                "options",
            ):
                continue
            for status, response in operation.get("responses", {}).items():
                if not str(status).isdigit() or not 200 <= int(status) <= 599:
                    continue
                content = response.get("content", {}).get("application/json", {})
                example = content.get("example")
                if example is None:
                    examples = content.get("examples", {})
                    example = next(
                        (
                            value.get("value")
                            for value in examples.values()
                            if isinstance(value, dict) and "value" in value
                        ),
                        {},
                    )
                r = default_rule()
                r.update(
                    name=operation.get("operationId") or f"{method.upper()} {path}",
                    method=method.upper(),
                    path=path,
                    status=int(status),
                    body=json.dumps(example, ensure_ascii=False),
                    enabled=False,
                )
                if "{" in path:
                    chunks = re.split(r"(\{[^}]+\})", path)
                    r["path"] = (
                        "^"
                        + "".join(
                            "[^/]+" if part.startswith("{") else re.escape(part)
                            for part in chunks
                        )
                        + "$"
                    )
                    r["match"] = "regex"
                rules.append(r)
                break
    return rules
