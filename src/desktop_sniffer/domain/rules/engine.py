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

        previous = {
            r["id"]: {k: v for k, v in r.items() if k != "_regex"} for r in self.rules
        }
        self.rules = []
        for r in rules:
            r_copy = dict(r)
            if r_copy.get("match") == "regex" and r_copy.get("path"):
                try:
                    r_copy["_regex"] = re.compile(r_copy["path"])
                except re.error:
                    pass
            self.rules.append(r_copy)

        self.hits = {
            r["id"]: self.hits[r["id"]]
            for r in rules
            if r["id"] in self.hits and previous.get(r["id"]) == r
        }
        scenarios = {r.get("scenario") for r in rules if r.get("scenario")}
        self.states = {
            key: value for key, value in self.states.items() if key in scenarios
        }

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

            if method != "*" and method.upper() != request["method"].upper():
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

    def explain(self, request):
        """Explain every candidate without reserving hits or changing scenarios."""
        parsed = urlsplit(request["url"])
        query = parse_qs(parsed.query, keep_blank_values=True)
        headers = {}
        for name, value in request.get("headers", []):
            headers.setdefault(name.lower(), []).append(value)
        try:
            body = json.loads(request.get("body", b""))
        except (ValueError, UnicodeError, TypeError):
            body = None
        results = []
        for index, rule in enumerate(self.rules):
            reasons = []
            if not rule.get("enabled", True):
                reasons.append("disabled")
            if rule.get("method", "*") not in ("*", request["method"].upper()):
                reasons.append("method mos emas")
            if (
                rule.get("host")
                and rule["host"].lower() != (parsed.hostname or "").lower()
            ):
                reasons.append("host mos emas")
            path, target = parsed.path or "/", rule.get("path", "")
            mode = rule["match"]
            if (
                (mode == "exact" and path != target)
                or (mode == "prefix" and not path.startswith(target))
                or (mode == "regex" and not re.search(target, path))
            ):
                reasons.append("path/" + mode + " mos emas")
            for condition in rule.get("conditions", []):
                values = (
                    query.get(condition["key"], [])
                    if condition["source"] == "query"
                    else headers.get(condition["key"].lower(), [])
                    if condition["source"] == "header"
                    else json_values(body, condition["key"])
                )
                if not compare(values, condition["op"], condition.get("value", "")):
                    reasons.append(
                        f"{condition['source']}.{condition['key']} {condition['op']} mos emas"
                    )
            if (
                rule.get("max_hits")
                and self.hits.get(rule["id"], 0) >= rule["max_hits"]
            ):
                reasons.append("max_hits tugagan")
            scenario = rule.get("scenario")
            if scenario and self.states.get(scenario, "Started") != (
                rule.get("state") or "Started"
            ):
                reasons.append("scenario state mos emas")
            results.append(
                {
                    "id": rule["id"],
                    "name": rule.get("name", ""),
                    "action": rule["action"],
                    "priority": index + 1,
                    "matched": not reasons,
                    "reasons": reasons,
                }
            )
        return results
