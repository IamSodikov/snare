import queue
import threading
from collections import deque

from desktop_sniffer.core.constants import CAPTURE_QUEUE_SIZE
from desktop_sniffer.infrastructure.persistence.store import Store


class CaptureWriter:
    def __init__(self, store: Store):
        self.store = store

        self._queue = queue.Queue(maxsize=CAPTURE_QUEUE_SIZE)
        self._stopping = threading.Event()

        self._errors = deque(maxlen=20)
        self._errors_lock = threading.Lock()

        self._thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return

        self._stopping.clear()

        self._thread = threading.Thread(
            target=self._run,
            name="capture-writer",
            daemon=True,
        )
        self._thread.start()

    def submit(self, document: dict) -> bool:
        if self._stopping.is_set():
            return False

        try:
            self._queue.put_nowait(document)
            return True
        except queue.Full:
            return False

    def pop_errors(self) -> list[str]:
        with self._errors_lock:
            errors = list(self._errors)
            self._errors.clear()

        return errors

    def stop(self, timeout: float = 3):
        self._stopping.set()

        if self._thread:
            self._thread.join(timeout=timeout)

    def _run(self):
        while not self._stopping.is_set() or not self._queue.empty():
            try:
                document = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                self.store.save_capture(document)

            except Exception as exc:
                with self._errors_lock:
                    self._errors.append(str(exc))

            finally:
                self._queue.task_done()