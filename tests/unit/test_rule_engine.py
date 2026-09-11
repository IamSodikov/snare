import pytest

from desktop_sniffer.domain.rules.defaults import default_rule
from desktop_sniffer.domain.rules.engine import RuleEngine
from desktop_sniffer.domain.rules.validation import validate_rules


def request(
    url="https://api.example.com/v1/profile",
    method="GET",
    headers=None,
    body=b"",
):
    return {
        "url": url,
        "method": method,
        "headers": headers or [],
        "body": body,
    }


def test_exact_match():
    rule = default_rule()
    rule.update({
        "host": "api.example.com",
        "path": "/v1/profile",
    })

    engine = RuleEngine()
    engine.replace_rules([rule])

    assert engine.select(request(), {"local"})["id"] == rule["id"]

    assert engine.select(
        request(url="https://api.example.com/other"),
        {"local"},
    ) is None


def test_conditions():
    rule = default_rule()
    rule.update({
        "method": "POST",
        "host": "api.example.com",
        "path": "/v1/profile",
        "conditions": [
            {
                "source": "query",
                "key": "mode",
                "op": "equals",
                "value": "test",
            },
            {
                "source": "header",
                "key": "x-client",
                "op": "equals",
                "value": "desktop",
            },
            {
                "source": "json",
                "key": "user.id",
                "op": "equals",
                "value": "7",
            },
        ],
    })

    engine = RuleEngine()
    engine.replace_rules([rule])

    result = engine.select(
        request(
            url="https://api.example.com/v1/profile?mode=test",
            method="POST",
            headers=[["X-Client", "desktop"]],
            body=b'{"user":{"id":7}}',
        ),
        {"local"},
    )

    assert result is not None


def test_scenario_sequence():
    first = default_rule()
    first.update({
        "path": "/",
        "scenario": "demo",
        "state": "Started",
        "next_state": "Second",
    })

    second = default_rule()
    second.update({
        "path": "/",
        "scenario": "demo",
        "state": "Second",
        "next_state": "Started",
    })

    engine = RuleEngine()
    engine.replace_rules([first, second])

    data = request(url="https://example.com/")

    assert engine.select(data, {"local"})["id"] == first["id"]
    assert engine.select(data, {"local"})["id"] == second["id"]
    assert engine.select(data, {"local"})["id"] == first["id"]


def test_max_hits():
    rule = default_rule()
    rule.update({
        "path": "/",
        "max_hits": 1,
    })

    engine = RuleEngine()
    engine.replace_rules([rule])

    data = request(url="https://example.com/")

    assert engine.select(data, {"local"}) is not None
    assert engine.select(data, {"local"}) is None


def test_disabled_rule():
    rule = default_rule()
    rule.update({
        "path": "/",
        "enabled": False,
    })

    engine = RuleEngine()
    engine.replace_rules([rule])

    assert engine.select(
        request(url="https://example.com/"),
        {"local"},
    ) is None


def test_invalid_regex():
    rule = default_rule()
    rule.update({
        "match": "regex",
        "path": "[",
    })

    with pytest.raises(ValueError):
        validate_rules([rule])


def test_request_patch_rule_is_valid():
    rule = default_rule()
    rule.update({
        "action": "request_patch",
        "status": 0,
        "preserve_body": True,
    })

    validate_rules([rule])
