from desktop_sniffer.domain.rules.patching import apply_patch, deep_diff


def test_deep_diff_and_apply():
    orig = {"user": "Ali", "age": 20, "config": {"theme": "dark", "lang": "en"}}
    edit = {"user": "Ali", "age": 99, "config": {"theme": "light"}}

    patch = deep_diff(orig, edit)
    assert patch["__snare_patch__"] == 2
    assert apply_patch(orig, patch) == edit

    live = {
        "user": "Vali",
        "age": 25,
        "config": {"theme": "dark", "lang": "uz", "new": "val"},
    }
    patched = apply_patch(live, patch)

    assert patched == {
        "user": "Vali",
        "age": 99,
        "config": {"theme": "light", "new": "val"},
    }


def test_deep_diff_no_changes():
    orig = {"a": 1}
    edit = {"a": 1}
    patch = deep_diff(orig, edit)
    assert patch is None
