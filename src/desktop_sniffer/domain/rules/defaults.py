import uuid


def default_rule() -> dict:
    return {
        "id": str(uuid.uuid4()),
        "name": "New mock",
        "enabled": True,
        "method": "GET",
        "rewrite_method": "",
        "rewrite_url": "",
        "host": "",
        "path": "/",
        "match": "exact",
        "conditions": [],
        "action": "local",
        "status": 200,
        "headers": [
            ["Content-Type", "application/json"],
        ],
        "remove_headers": [],
        "body": "{}",
        "fixture": None,
        "preserve_body": False,
        "delay_ms": 0,
        "scenario": "",
        "state": "Started",
        "next_state": "",
        "max_hits": 0,
    }
