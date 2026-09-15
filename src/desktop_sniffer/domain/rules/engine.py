import json
import re
from urllib.parse import parse_qs, urlsplit

from desktop_sniffer.domain.rules.matching import compare, json_values
from desktop_sniffer.domain.rules.validation import validate_rules


class RuleEngine:
    def __init__(self):
        self.rules = []
        self.hits = {}
        self.states = {}

    def replace_rules(self, rules):
        validate_rules(rules)

        self.rules = []
        for r in rules:
            r_copy = dict(r)
            if r_copy.get("match") == "regex" and r_copy.get("path"):
                try:
                    r_copy["_regex"] = re.compile(r_copy["path"])
                except re.error:
                    pass
            self.rules.append(r_copy)

        self.hits.clear()
        self.states.clear()

    def select(self, request: dict, actions: set[str]):
        parsed = urlsplit(request["url"])
        query = parse_qs(parsed.query, keep_blank_values=True)

        request_headers = {}

        for name, value in request.get("headers", []):
            request_headers.setdefault(name.lower(), []).append(value)

        body_parsed = False
        body = None
        body_valid = False

        def get_json_body():
            nonlocal body_parsed, body, body_valid
            if not body_parsed:
                body_parsed = True
                try:
                    body = json.loads(request.get("body", b""))
                    body_valid = True
                except (ValueError, UnicodeError, TypeError):
                    pass
            return body, body_valid

        for rule in self.rules:
            if not rule.get("enabled", True):
                continue

            if rule["action"] not in actions:
                continue

            method = rule.get("method", "*")

            if (
                method != "*"
                and method.upper() != request["method"].upper()
            ):
                continue

            host = rule.get("host", "").lower()

            if host and host != (parsed.hostname or "").lower():
                continue

            path = parsed.path or "/"
            target = rule.get("path", "")
            mode = rule["match"]

            if mode == "exact" and path != target:
                continue

            if mode == "prefix" and not path.startswith(target):
                continue

            if mode == "regex":
                regex = rule.get("_regex")
                if regex:
                    if regex.search(path) is None:
                        continue
                elif re.search(target, path) is None:
                    continue

            matched = True

            for condition in rule.get("conditions", []):
                source = condition["source"]
                key = condition["key"]

                if source == "query":
                    values = query.get(key, [])
                elif source == "header":
                    values = request_headers.get(key.lower(), [])
                else:
                    b, b_valid = get_json_body()
                    values = json_values(b, key) if b_valid else []

                if not compare(
                    values,
                    condition["op"],
                    condition.get("value", ""),
                ):
                    matched = False
                    break

            if not matched:
                continue

            maximum = rule.get("max_hits", 0)
            hit_count = self.hits.get(rule["id"], 0)

            if maximum and hit_count >= maximum:
                continue

            scenario = rule.get("scenario", "")

            if scenario:
                current_state = self.states.get(scenario, "Started")
                required_state = rule.get("state", "") or "Started"

                if current_state != required_state:
                    continue

            # Reservation await/delay'dan oldin bajariladi.
            self.hits[rule["id"]] = hit_count + 1

            if scenario and rule.get("next_state"):
                self.states[scenario] = rule["next_state"]

            return rule

        return None