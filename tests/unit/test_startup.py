import subprocess
import sys


def test_windowed_startup_records_failure_with_missing_streams(tmp_path):
    code = """
import os
import sys
from pathlib import Path
from desktop_sniffer import app

os.environ['LOCALAPPDATA'] = sys.argv[1]
sys.frozen = True
sys.platform = 'linux'
sys.stdout = None
sys.stderr = None

def fail():
    assert sys.stdout is not None
    assert sys.stderr is not None
    raise RuntimeError('startup-test-error')

app.run_application = fail
try:
    app.main()
except RuntimeError:
    pass
else:
    raise AssertionError('Startup error was swallowed')

path = Path(sys.argv[1]) / 'Snare' / 'logs' / 'startup.log'
assert 'startup-test-error' in path.read_text()
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path)],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_source_startup_does_not_replace_streams(monkeypatch):
    from desktop_sniffer.app import configure_frozen_logging

    monkeypatch.delattr(sys, 'frozen', raising=False)
    stdout, stderr = sys.stdout, sys.stderr
    assert configure_frozen_logging() is None
    assert sys.stdout is stdout
    assert sys.stderr is stderr
