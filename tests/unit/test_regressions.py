import asyncio
import base64
import copy
import json
import time
import types

import pytest

from desktop_sniffer.domain.rules.defaults import default_rule
from desktop_sniffer.domain.rules.engine import RuleEngine
from desktop_sniffer.domain.rules.patching import apply_patch, deep_diff
from desktop_sniffer.infrastructure.persistence.store import Store


@pytest.mark.parametrize(
    "value", [None, False, 0, [], {}, "__SNARE_DELETE_FIELD__", {"nested": None}]
)
def test_patch_all_json_values(value):
    before = {"a": 1, "keep": 7}
    after = {"a": value, "keep": 7}
    patch = deep_diff(before, after)
    assert apply_patch(before, patch) == after
    assert apply_patch({"a": 9, "keep": 8}, patch) == {"a": value, "keep": 8}
    assert before == {"a": 1, "keep": 7}


def test_patch_remove_and_legacy():
    assert apply_patch({"a": 1, "b": 2}, deep_diff({"a": 1, "b": 2}, {"b": 3})) == {"b": 3}
    assert apply_patch({"a": 1}, {"a": "__SNARE_DELETE_FIELD__"}) == {}


def test_unrelated_rule_keeps_counters():
    r = default_rule()
    r["max_hits"] = 1
    r["scenario"] = "retry"
    r["next_state"] = "Done"
    engine = RuleEngine()
    engine.replace_rules([r])
    request = {"method": "GET", "url": "http://example.com/"}
    assert engine.select(request, {"local"})
    unrelated = default_rule()
    unrelated["path"] = "/other"
    engine.replace_rules([r, unrelated])
    assert engine.hits[r["id"]] == 1 and engine.states["retry"] == "Done"
    assert engine.select(request, {"local"}) is None


def document(i, body=b'{"balance":10}'):
    snap = {
        "headers": [["Content-Type", "application/json"], ["X-Test", "old"]],
        "body_b64": base64.b64encode(body).decode(),
        "body_size": len(body),
        "truncated": False,
    }
    return {
        "id": str(i),
        "created": time.time(),
        "method": "POST",
        "url": "http://api.test/rpc",
        "request": copy.deepcopy(snap),
        "final": dict(snap, status=200),
    }


def test_retention_exact_with_equal_timestamps(tmp_path, monkeypatch):
    import desktop_sniffer.infrastructure.persistence.store as module

    monkeypatch.setattr(module, "CAPTURE_RETENTION", 3)
    s = Store(tmp_path)
    timestamp = time.time()
    for i in range(5):
        d = document(i)
        d["created"] = timestamp
        s.save_capture(d)
    assert s.statistics()["count"] == 3


def test_record_off_and_redaction(tmp_path):
    s = Store(tmp_path)
    s.save_settings({"record": False})
    s.save_capture(document(1))
    assert not s.documents()
    s.save_settings({"record": True, "redact": True})
    d = document(1, b'{"token":"secret","data":1}')
    d["request"]["headers"] = [["Authorization", "Bearer secret"]]
    s.save_capture(d)
    saved = s.capture("1")
    assert saved["request"]["headers"][0][1] == "<redacted>"
    assert json.loads(base64.b64decode(saved["request"]["body_b64"]))["token"] == "<redacted>"
    assert d["request"]["headers"][0][1] == "Bearer secret"


def test_proxy_restore_keeps_user_external_changes(tmp_path, monkeypatch):
    from desktop_sniffer.core.system_proxy import SystemProxy

    monkeypatch.setitem(
        __import__("sys").modules,
        "winreg",
        types.SimpleNamespace(REG_DWORD=4, REG_SZ=1),
    )
    before = {
        "ProxyEnable": [1, 4],
        "ProxyServer": ["corp:123", 1],
        "ProxyOverride": None,
        "AutoConfigURL": ["https://corp/pac", 1],
        "AutoDetect": [1, 4],
    }
    values = copy.deepcopy(before)
    monkeypatch.setattr(SystemProxy, "supported", staticmethod(lambda: True))
    monkeypatch.setattr(SystemProxy, "_read", staticmethod(lambda: copy.deepcopy(values)))
    monkeypatch.setattr(SystemProxy, "_write", staticmethod(lambda changes: values.update(changes)))
    proxy = SystemProxy(tmp_path / "recovery.json")
    proxy.enable(8080)
    proxy.enable(9090)
    values["ProxyOverride"] = ["user-choice", 1]
    proxy.restore()
    assert values["ProxyServer"] == before["ProxyServer"]
    assert values["AutoConfigURL"] == before["AutoConfigURL"]
    assert values["ProxyOverride"] == ["user-choice", 1]
    assert not proxy.recovery_path.exists()


def test_headers_only_request_rule_can_be_saved(qapp, tmp_path):
    from desktop_sniffer.ui.dialogs.rule_dialog import RuleDialog

    s = Store(tmp_path)
    r = default_rule()
    r.update(action="request_patch", status=0, preserve_body=True)
    dialog = RuleDialog(s, r)
    dialog.save()
    assert dialog.result_rule["preserve_body"] and dialog.result_rule["action"] == "request_patch"


def test_edit_patch_recomputes_from_base(qapp, tmp_path):
    from desktop_sniffer.ui.dialogs.rule_dialog import RuleDialog

    s = Store(tmp_path)
    r = default_rule()
    r.update(
        action="patch",
        status=0,
        body_base='{"balance":10}',
        body='{"balance":20}',
        body_patch=deep_diff({"balance": 10}, {"balance": 20}),
    )
    dialog = RuleDialog(s, r)
    dialog.body.setPlainText('{"balance":30}')
    dialog.save()
    assert apply_patch({"balance": 10, "keep": True}, dialog.result_rule["body_patch"]) == {
        "balance": 30,
        "keep": True,
    }


def test_switch_request_to_local_has_valid_status(qapp, tmp_path):
    from desktop_sniffer.ui.dialogs.rule_dialog import RuleDialog

    dialog = RuleDialog(Store(tmp_path))
    dialog.action.setCurrentIndex(dialog.action.findData("request_patch"))
    dialog.action.setCurrentIndex(dialog.action.findData("local"))
    dialog.save()
    assert dialog.result_rule["status"] == 200


def test_small_window_and_consistent_style(window, qapp):
    window.show()
    window.resize(1024, 768)
    qapp.processEvents()
    assert window.width() <= 1024
    assert qapp.font().family() == "Noto Sans"
    assert "fusion" in qapp.style().objectName().lower() or qapp.style().objectName() == ""


def test_dirty_selection_is_preserved(window, qapp, monkeypatch):
    from PySide6.QtWidgets import QMessageBox

    page = window.captures_page
    page.store.save_capture(document(1))
    page.store.save_capture(document(2))
    page.refresh(force=True)
    page.table.selectRow(0)
    page.begin_edit("res")
    page.res_body.setPlainText('{"balance":99}')
    assert page._dirty
    selected = page.selected_id
    monkeypatch.setattr(QMessageBox, "question", lambda *a: QMessageBox.StandardButton.No)
    page.table.selectRow(1)
    qapp.processEvents()
    assert page.selected_id == selected and page.res_body.toPlainText() == '{"balance":99}'


def test_truncated_body_guard(window, monkeypatch):
    from PySide6.QtWidgets import QMessageBox

    monkeypatch.setattr(QMessageBox, "warning", lambda *a: None)
    page = window.captures_page
    assert not page.guard_body({"truncated": True}, True)
    assert page.guard_body({"truncated": True}, False)


def test_large_body_preview_avoids_full_widget(qapp):
    from desktop_sniffer.ui.pages.captures_page import BodyTextEdit

    body = "x" * 2_000_000
    widget = BodyTextEdit()
    widget.setPlainText(body)
    assert widget.toPlainText() == body and widget.document().characterCount() < 66000


def test_har_sanitized_roundtrip(tmp_path):
    from desktop_sniffer.services.traffic_tools import export_har, import_har

    s = Store(tmp_path / "a")
    s.save_capture(document(1, b'{"token":"secret"}'))
    path = tmp_path / "test.har"
    export_har(s, path)
    other = Store(tmp_path / "b")
    assert import_har(other, path) == 1
    assert (
        json.loads(base64.b64decode(other.documents()[0]["request"]["body_b64"]))["token"]
        == "<redacted>"
    )


def test_curl_truncated_rejected():
    from desktop_sniffer.services.traffic_tools import curl_command

    d = document(1)
    d["request"]["truncated"] = True
    with pytest.raises(ValueError):
        curl_command(d)


def test_openapi_disabled_regex():
    from desktop_sniffer.services.openapi_tools import rules_from_openapi

    doc = {
        "paths": {
            "/user/{id}": {
                "get": {
                    "responses": {
                        "200": {"content": {"application/json": {"example": {"ok": True}}}}
                    }
                }
            }
        }
    }
    rules = rules_from_openapi(doc)
    assert len(rules) == 1 and not rules[0]["enabled"] and rules[0]["match"] == "regex"


def test_pending_and_original_request(tmp_path, monkeypatch):
    from mitmproxy import http

    from desktop_sniffer.infrastructure.mitmproxy.addon import DesktopAddon

    monkeypatch.setenv("SNIFFER_WORKSPACE", str(tmp_path))
    addon = DesktopAddon()
    captured = []
    monkeypatch.setattr(addon.capture_writer, "submit", lambda d: captured.append(d) or True)
    monkeypatch.setattr(addon, "reload_rules", lambda: None)
    r = default_rule()
    r.update(
        action="request_patch",
        status=0,
        method="POST",
        path="/rpc",
        body='{"edited":true}',
    )
    addon.engine.replace_rules([r])
    flow = http.HTTPFlow(None, None)
    flow.request = http.Request.make("POST", "http://api.test/rpc", b'{"old":true}')
    asyncio.run(addon.request(flow))
    assert captured[0]["pending"]
    assert (
        base64.b64decode(flow.metadata["desktop_request_original"]["body_b64"]) == b'{"old":true}'
    )
    assert flow.request.content == b'{"edited":true}'
    flow.response = http.Response.make(200, b"{}")
    asyncio.run(addon.response(flow))
    assert not captured[-1]["pending"] and captured[-1]["applied_rules"][0]["id"] == r["id"]


def test_restart_kill_is_cancelled(qapp, tmp_path):
    from desktop_sniffer.services.engine_process import EngineProcess

    engine = EngineProcess()
    engine._kill_timer.start(3000)
    engine._on_finished(0)
    assert not engine._kill_timer.isActive()


def test_explain_does_not_reserve_hits():
    engine = RuleEngine()
    r = default_rule()
    r["max_hits"] = 1
    engine.replace_rules([r])
    reports = engine.explain({"method": "POST", "url": "http://example.com/no"})
    assert not reports[0]["matched"] and "method mos emas" in reports[0]["reasons"]
    assert engine.hits == {} and engine.states == {}


def test_json_tree_large_is_bounded(qapp):
    from desktop_sniffer.ui.pages.captures_page import JsonTreeDialog
    from PySide6.QtWidgets import QTreeWidget

    dialog = JsonTreeDialog(json.dumps({str(i): i for i in range(10000)}))
    tree = dialog.findChild(QTreeWidget)
    assert tree.topLevelItem(0).childCount() == 501


def test_writer_coalesces_pending_and_final(tmp_path):
    from desktop_sniffer.infrastructure.mitmproxy.capture_writer import CaptureWriter

    writer = CaptureWriter(Store(tmp_path))
    d = document(1)
    d["pending"] = True
    assert writer.submit(d)
    final = copy.deepcopy(d)
    final["pending"] = False
    assert writer.submit(final) and writer._queue.qsize() == 1
    writer.start()
    writer.stop()
    assert writer.store.capture("1")["pending"] is False


def test_update_urls_and_tls():
    import ssl
    from desktop_sniffer.core.updater import valid_url, get_ssl_context

    assert get_ssl_context().verify_mode == ssl.CERT_REQUIRED
    for url in [
        "http://github.com/file",
        "https://evil.test/file",
        "https://github.com@evil.test/file",
    ]:
        with pytest.raises(ValueError):
            valid_url(url)
    assert valid_url("https://github.com/IamSodikov/snare/releases/download/v1/file")


def test_download_rejects_wrong_hash(qapp, tmp_path, monkeypatch):
    from desktop_sniffer.core import updater

    class Response:
        headers = {"Content-Length": "5"}

        def __init__(self):
            self.reads = 0

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, n):
            self.reads += 1
            return b"hello" if self.reads == 1 else b""

    monkeypatch.setattr(updater, "open_url", lambda *a: Response())
    monkeypatch.setattr(updater.tempfile, "mkdtemp", lambda **a: str(tmp_path))
    download = updater.DownloadThread("https://github.com/file", "0" * 64)
    errors = []
    completed = []
    download.error.connect(errors.append)
    download.completed.connect(completed.append)
    download.run()
    assert errors and not completed and not list(tmp_path.glob("Snare-*"))


def test_sse_frames_and_websocket_messages(tmp_path, monkeypatch):
    from mitmproxy import http
    from desktop_sniffer.infrastructure.mitmproxy.addon import DesktopAddon

    monkeypatch.setenv("SNIFFER_WORKSPACE", str(tmp_path))
    addon = DesktopAddon()
    documents = []
    monkeypatch.setattr(addon.capture_writer, "submit", lambda d: documents.append(d) or True)
    flow = http.HTTPFlow(None, None)
    flow.request = http.Request.make("GET", "http://api.test/events")
    flow.response = http.Response.make(200, b"", {"Content-Type": "text/event-stream"})
    addon.responseheaders(flow)
    chunk = b'data: {"ok":true}\r\n\r\n'
    assert flow.response.stream(chunk) == chunk
    assert documents[-1]["messages"][0]["text"] == 'data: {"ok":true}'
    flow.websocket = types.SimpleNamespace(
        messages=[types.SimpleNamespace(from_client=True, timestamp=time.time(), content=b"hello")]
    )
    addon.websocket_message(flow)
    assert documents[-1]["messages"][-1]["direction"] == "client"


def test_invalid_rules_startup_recovery(window):

    root = window.store.root
    window.store.save_rules([default_rule()])
    window.store.save_rules([default_rule()])
    (root / "rules.json").write_text("broken", encoding="utf-8")
    window.recover_workspace(root.name)
    assert window.store.load_rules()
    assert list(root.glob("rules.invalid-*.json"))


def test_frozen_engine_log_channel(qapp, tmp_path):
    from desktop_sniffer.services.engine_process import EngineProcess

    engine = EngineProcess()
    engine._log_path = tmp_path / "engine.log"
    logs = []
    engine.log_received.connect(logs.append)
    engine._log_path.write_text("SNARE_", encoding="utf-8")
    engine._read_logs()
    assert not engine._addon_ready
    with engine._log_path.open("a", encoding="utf-8") as stream:
        stream.write("READY\nproxy request\n")
    engine._read_logs()
    assert engine._addon_ready
    assert "proxy request" in logs[-1]
    previous = list(logs)
    engine._read_logs()
    assert logs == previous


def test_engine_button_shows_each_lifecycle_state(window, monkeypatch):
    for message, state, label in (
        ("Engine ishga tushirilmoqda…", "starting", "Starting"),
        ("Proxy: 127.0.0.1:8080", "running", "Running"),
        ("Engine to‘xtatilmoqda…", "stopping", "Stopping"),
        ("Engine to‘xtatilgan", "stopped", "Start"),
        ("Engine to‘xtadi: 1", "error", "Error"),
    ):
        window.set_status(message)
        assert window.engine_toggle.property("engineState") == state
        assert label in window.engine_toggle.text()
    window.set_status("Engine to‘xtatilgan")
    calls = []
    monkeypatch.setattr(window, "restart_engine", lambda: calls.append("start"))
    window.engine_toggle.click()
    assert calls == ["start"]
    window.show_engine_error("test failure")
    window.set_status("Engine to‘xtatilgan")
    assert window.engine_toggle.property("engineState") == "error"


def test_body_click_edits_inline_and_discard_restores(window, qapp):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest

    page = window.captures_page
    page.store.save_capture(document(1))
    page.refresh(force=True)
    page.table.selectRow(0)
    page.details.setCurrentIndex(1)
    window.show()
    qapp.processEvents()
    initial = page.res_body.toPlainText()
    QTest.mouseClick(page.res_body.viewport(), Qt.MouseButton.LeftButton)
    assert not page.res_body.isReadOnly()
    page.res_body.selectAll()
    page.res_body.insertPlainText('{"balance":42}')
    assert page.res_body.toPlainText() == '{"balance":42}'
    assert page._dirty and not page.res_save_btn.isHidden()
    page.discard()
    assert page.res_body.toPlainText() == initial and not page._dirty
    page.res_view.setCurrentText("Diff")
    QTest.mouseClick(page.res_body.viewport(), Qt.MouseButton.LeftButton)
    assert page.res_body.isReadOnly() and not page._dirty


def test_hover_actions_target_row_and_play_resumes_view(window, qapp, monkeypatch):
    from PySide6.QtTest import QTest

    page = window.captures_page
    for i in (1, 2):
        page.store.save_capture(document(i))
    page.refresh(force=True)
    page.table.selectRow(0)
    selected = page.selected_id
    window.show()
    qapp.processEvents()
    page.proxy_ready = True
    QTest.mouseMove(
        page.table.viewport(), page.table.visualItemRect(page.table.item(1, 0)).center()
    )
    qapp.processEvents()
    target = page.hover_id
    assert target != selected and page.row_actions.isVisible()
    calls = []
    monkeypatch.setattr(page, "replay", lambda fid=None: calls.append(fid))
    page.row_replay.click()
    assert calls == [target] and page.selected_id == selected
    page.row_pin.click()
    assert target in page.pinned and page.selected_id == selected
    page.show_row_actions(1)
    assert page.row_pin.text() == "Unpin"
    page.row_pin.click()
    assert target not in page.pinned
    page.pause.setChecked(True)
    page.store.save_capture(document(3))
    page.refresh()
    assert page.table.rowCount() == 2
    page.show_row_actions(0)
    assert page.row_play.isVisible()
    page.row_play.click()
    assert not page.pause.isChecked() and page.table.rowCount() == 3


def test_direct_header_edit_marks_draft(window):
    page = window.captures_page
    page.store.save_capture(document(1))
    page.refresh(force=True)
    page.table.selectRow(0)
    page.req_url.setText("https://api.test/edited")
    assert page._dirty and not page.req_save_btn.isHidden()
    # A draft in a hidden tab must still survive edits in the other tab.
    page.details.setCurrentIndex(1)
    page.check_res_changes()
    assert page._dirty
