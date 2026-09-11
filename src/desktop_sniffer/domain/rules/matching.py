import json
import re


def as_text(value) -> str:
    if isinstance(value, str):
        return value

    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def json_values(document, path: str) -> list[str]:
    current = document

    try:
        for part in path.split(".") if path else []:
            if isinstance(current, list):
                current = current[int(part)]
            else:
                current = current[part]

        return [as_text(current)]

    except (KeyError, IndexError, TypeError, ValueError):
        return []


def compare(values: list[str], operator: str, expected: str) -> bool:
    if operator == "exists":
        return bool(values)

    if operator == "absent":
        return not values

    if operator == "equals":
        return any(value == expected for value in values)

    if operator == "contains":
        return any(expected in value for value in values)

    if operator == "regex":
        return any(
            re.search(expected, value) is not None
            for value in values
        )

    return False