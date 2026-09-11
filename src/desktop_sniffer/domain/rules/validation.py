import re


ACTIONS = ("local", "replace", "patch", "request_patch")
MATCH_MODES = ("exact", "prefix", "regex")
OPERATORS = ("equals", "contains", "regex", "exists", "absent")
SOURCES = ("query", "header", "json")

HEADER_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")


def validate_regex(pattern: str):
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Noto‘g‘ri regex: {exc}") from exc


def validate_rules(rules):
    if not isinstance(rules, list):
        raise ValueError("Rules list bo‘lishi kerak")

    seen_ids = set()

    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("Har bir qoida object bo‘lishi kerak")

        rule_id = rule.get("id")

        if not isinstance(rule_id, str) or not rule_id:
            raise ValueError("Rule ID majburiy")

        if rule_id in seen_ids:
            raise ValueError("Takrorlangan rule ID")

        seen_ids.add(rule_id)

        for field in (
            "name",
            "method",
            "rewrite_method",
            "rewrite_url",
            "host",
            "path",
            "body",
            "scenario",
            "state",
            "next_state",
        ):
            if not isinstance(rule.get(field, ""), str):
                raise ValueError(f"{field}: text kutilmoqda")

        if type(rule.get("enabled", True)) is not bool:
            raise ValueError("enabled boolean bo‘lishi kerak")

        if rule.get("action") not in ACTIONS:
            raise ValueError("Noto‘g‘ri action")

        if rule.get("match") not in MATCH_MODES:
            raise ValueError("Noto‘g‘ri matching mode")

        method = rule.get("method", "*")

        if method != "*" and not HEADER_NAME.fullmatch(method):
            raise ValueError("Noto‘g‘ri HTTP method")

        rewrite_method = rule.get("rewrite_method", "")

        if rewrite_method and not HEADER_NAME.fullmatch(rewrite_method):
            raise ValueError("Noto‘g‘ri rewrite HTTP method")

        if rule["match"] == "regex":
            validate_regex(rule.get("path", ""))

        status = rule.get("status", 200)

        if type(status) is not int:
            raise ValueError("Status integer bo‘lishi kerak")

        if status == 0:
            if rule["action"] not in ("patch", "request_patch"):
                raise ValueError("Status 0 faqat patch uchun")
        elif not 200 <= status <= 599:
            raise ValueError("Status 200–599 oralig‘ida bo‘lishi kerak")

        if rule["action"] == "request_patch" and status != 0:
            raise ValueError("Request patch uchun status 0 bo‘lishi kerak")

        for field, maximum in (
            ("delay_ms", 120_000),
            ("max_hits", 1_000_000),
        ):
            value = rule.get(field, 0)

            if type(value) is not int or not 0 <= value <= maximum:
                raise ValueError(f"Noto‘g‘ri {field}")

        fixture = rule.get("fixture")

        if fixture is not None and (
            not isinstance(fixture, str) or not fixture
        ):
            raise ValueError("Noto‘g‘ri fixture ID")

        preserve = rule.get("preserve_body", False)

        if type(preserve) is not bool:
            raise ValueError("preserve_body boolean bo‘lishi kerak")

        if preserve and rule["action"] not in ("patch", "request_patch"):
            raise ValueError("preserve_body faqat patch uchun")

        if preserve and fixture:
            raise ValueError("Preserve body va fixture birga ishlatilmaydi")

        headers = rule.get("headers", [])

        if not isinstance(headers, list):
            raise ValueError("Headers list bo‘lishi kerak")

        for pair in headers:
            if not isinstance(pair, list) or len(pair) != 2:
                raise ValueError("Header formati: [name, value]")

            name, value = pair

            if not isinstance(name, str) or not isinstance(value, str):
                raise ValueError("Header name/value text bo‘lishi kerak")

            if not HEADER_NAME.fullmatch(name):
                raise ValueError(f"Noto‘g‘ri header nomi: {name}")

            if any(char in value for char in ("\r", "\n", "\0")):
                raise ValueError("Header qiymatida taqiqlangan belgi")

            try:
                value.encode("latin-1")
            except UnicodeEncodeError as exc:
                raise ValueError(
                    "Header qiymati Latin-1 bilan ifodalanishi kerak"
                ) from exc

        remove_headers = rule.get("remove_headers", [])

        if not isinstance(remove_headers, list):
            raise ValueError("remove_headers list bo‘lishi kerak")

        for name in remove_headers:
            if not isinstance(name, str) or not HEADER_NAME.fullmatch(name):
                raise ValueError("Noto‘g‘ri remove header nomi")

        conditions = rule.get("conditions", [])

        if not isinstance(conditions, list):
            raise ValueError("Conditions list bo‘lishi kerak")

        for condition in conditions:
            if not isinstance(condition, dict):
                raise ValueError("Condition object bo‘lishi kerak")

            if condition.get("source") not in SOURCES:
                raise ValueError("Noto‘g‘ri condition source")

            if condition.get("op") not in OPERATORS:
                raise ValueError("Noto‘g‘ri condition operator")

            if not isinstance(condition.get("key"), str):
                raise ValueError("Condition key text bo‘lishi kerak")

            if not isinstance(condition.get("value", ""), str):
                raise ValueError("Condition value text bo‘lishi kerak")

            if condition["op"] == "regex":
                validate_regex(condition.get("value", ""))
