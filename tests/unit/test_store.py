from desktop_sniffer.domain.rules.defaults import default_rule
from desktop_sniffer.infrastructure.persistence.store import Store


def test_rules_round_trip(tmp_path):
    store = Store(tmp_path / "workspace")
    rule = default_rule()

    store.save_rules([rule])

    assert store.load_rules() == [rule]


def test_fixture_round_trip(tmp_path):
    store = Store(tmp_path / "workspace")
    body = b"\x00\x01\xffbinary"

    fixture_id = store.put_fixture(body)

    assert store.fixture(fixture_id) == body


def test_bundle_round_trip(tmp_path):
    source = Store(tmp_path / "source")
    destination = Store(tmp_path / "destination")

    body = b"\x00\xfffixture"
    fixture_id = source.put_fixture(body)

    rule = default_rule()
    rule["fixture"] = fixture_id
    rule["body"] = ""

    source.save_rules([rule])

    bundle = tmp_path / "mocks.json"
    source.export_bundle(bundle)
    destination.import_bundle(bundle)

    imported = destination.load_rules()

    assert len(imported) == 1
    assert imported[0]["id"] != rule["id"]
    assert destination.fixture(imported[0]["fixture"]) == body