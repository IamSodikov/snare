import queue
import threading
from collections import deque
from desktop_sniffer.core.constants import CAPTURE_QUEUE_SIZE
from desktop_sniffer.infrastructure.persistence.store import Store


class CaptureWriter:
    """Coalesce flow updates and commit batches without blocking the proxy loop."""

    def __init__(self, store: Store):
        self.store = store
        self._queue = queue.Queue(maxsize=CAPTURE_QUEUE_SIZE)
        self._pending = {}
        self._pending_lock = threading.Lock()
        self._stopping = threading.Event()
        self._errors = deque(maxlen=20)
        self._errors_lock = threading.Lock()
        self._thread = None
        self.dropped = 0

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stopping.clear()
        self._thread = threading.Thread(
            target=self._run, name="capture-writer", daemon=True
        )
        self._thread.start()

    def submit(self, document):
        if self._stopping.is_set():
            return False
        key = document["id"]
        with self._pending_lock:
            if key in self._pending:
                self._pending[key] = document
                return True
            try:
                self._queue.put_nowait(key)
            except queue.Full:
                self.dropped += 1
                return False
            self._pending[key] = document
        return True

    def pop_errors(self):
        with self._errors_lock:
            errors = list(self._errors)
            self._errors.clear()
        return errors

    def stop(self, timeout=3):
        self._stopping.set()
        if self._thread:
            self._thread.join(timeout)

    def _run(self):
        while not self._stopping.is_set() or not self._queue.empty():
            try:
                key = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            keys = [key]
            while len(keys) < 16:
                try:
                    keys.append(self._queue.get_nowait())
                except queue.Empty:
                    break
            with self._pending_lock:
                documents = [self._pending.pop(key) for key in keys]
            try:
                self.store.save_capture_batch(documents)
            except Exception as exc:
                with self._errors_lock:
                    self._errors.append(str(exc))
            finally:
                for _ in keys:
                    self._queue.task_done()
