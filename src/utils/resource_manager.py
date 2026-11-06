import time
import multiprocessing
from contextlib import contextmanager
from config.settings import settings
from src.utils.queue import SlotUnavailableError


class ResourceManager:
    """
    Semaphore-based concurrency limiter shared across agent processes.

    Both semaphores use multiprocessing primitives so they work correctly
    when the ResourceManager is passed to child processes via
    multiprocessing.Process.  Usage counters and timing stats are also
    cross-process via multiprocessing.Value / multiprocessing.Lock.
    """

    def __init__(self, compilation_slots: int, verification_slots: int):
        self._compilation_total = compilation_slots
        self._verification_total = verification_slots

        self.compilation_slots = multiprocessing.Semaphore(compilation_slots)
        self.verification_slots = multiprocessing.Semaphore(verification_slots)

        # Cross-process counters — updated atomically under _lock.
        self._lock = multiprocessing.Lock()
        self._compilation_used        = multiprocessing.Value('i', 0)
        self._verification_used       = multiprocessing.Value('i', 0)
        self._compilation_acquisitions = multiprocessing.Value('i', 0)
        self._verification_acquisitions = multiprocessing.Value('i', 0)
        self._compilation_wait_total  = multiprocessing.Value('d', 0.0)
        self._verification_wait_total = multiprocessing.Value('d', 0.0)

        compiler_timeout = settings.queues.get("compiler_batch_timeout", 120)
        esbmc_timeout    = settings.esbmc.get("timeout", 300)
        self._compilation_timeout: int  = int(compiler_timeout) + 30
        self._verification_timeout: int = int(esbmc_timeout)    + 30

    # ------------------------------------------------------------------
    # Compilation slots
    # ------------------------------------------------------------------

    def get_compilation_slot(self) -> None:
        """Block until a compilation slot is free, then claim it.

        Raises:
            SlotUnavailableError: if no slot becomes available within the
                configured timeout (compiler_batch_timeout + 30 s).  This is a
                RetryableError, so the consumer re-queues the message instead of
                the agent recording a compilation failure against a snippet that
                was never actually compiled.
        """
        t0 = time.monotonic()
        acquired = self.compilation_slots.acquire(timeout=self._compilation_timeout)
        if not acquired:
            raise SlotUnavailableError(
                f"Timed out waiting for a compilation slot after "
                f"{self._compilation_timeout}s. A Docker container may be hung."
            )
        elapsed = time.monotonic() - t0
        with self._lock:
            self._compilation_used.value        += 1
            self._compilation_acquisitions.value += 1
            self._compilation_wait_total.value   += elapsed

    def release_compilation_slot(self) -> None:
        self.compilation_slots.release()
        with self._lock:
            self._compilation_used.value = max(0, self._compilation_used.value - 1)

    @contextmanager
    def compilation_slot(self):
        """Context manager — acquires a compilation slot and always releases it."""
        self.get_compilation_slot()
        try:
            yield
        finally:
            self.release_compilation_slot()

    # ------------------------------------------------------------------
    # Verification slots
    # ------------------------------------------------------------------

    def get_verification_slot(self) -> None:
        """Block until a verification slot is free, then claim it.

        Raises:
            SlotUnavailableError: if no slot becomes available within the
                configured timeout (esbmc_timeout + 30 s).  A RetryableError, so
                back-pressure re-queues the message rather than marking the
                snippet VERIFICATION_ERROR without ever running ESBMC on it.
        """
        t0 = time.monotonic()
        acquired = self.verification_slots.acquire(timeout=self._verification_timeout)
        if not acquired:
            raise SlotUnavailableError(
                f"Timed out waiting for a verification slot after "
                f"{self._verification_timeout}s. A Docker container may be hung."
            )
        elapsed = time.monotonic() - t0
        with self._lock:
            self._verification_used.value        += 1
            self._verification_acquisitions.value += 1
            self._verification_wait_total.value   += elapsed

    def release_verification_slot(self) -> None:
        self.verification_slots.release()
        with self._lock:
            self._verification_used.value = max(0, self._verification_used.value - 1)

    @contextmanager
    def verification_slot(self):
        """Context manager — acquires a verification slot and always releases it."""
        self.get_verification_slot()
        try:
            yield
        finally:
            self.release_verification_slot()

    # ------------------------------------------------------------------
    # Status snapshot
    # ------------------------------------------------------------------

    def get_status(self) -> dict:
        """Return a cross-process-safe snapshot of current slot utilisation."""
        with self._lock:
            c_used = self._compilation_used.value
            v_used = self._verification_used.value
            c_acq  = self._compilation_acquisitions.value
            v_acq  = self._verification_acquisitions.value
            c_wait = self._compilation_wait_total.value
            v_wait = self._verification_wait_total.value

        return {
            "compilation": {
                "total":              self._compilation_total,
                "used":               c_used,
                "free":               max(0, self._compilation_total - c_used),
                "total_acquisitions": c_acq,
                "avg_wait_s":         round(c_wait / c_acq, 3) if c_acq else 0.0,
            },
            "verification": {
                "total":              self._verification_total,
                "used":               v_used,
                "free":               max(0, self._verification_total - v_used),
                "total_acquisitions": v_acq,
                "avg_wait_s":         round(v_wait / v_acq, 3) if v_acq else 0.0,
            },
        }
