"""Cooperative shutdown for agent processes.

``main.py`` sends SIGTERM and waits before escalating to SIGKILL.  Without a
handler, SIGTERM kills the process immediately: in-flight Docker containers are
orphaned, and the batch currently being processed dies between its database write
and its next-stage publish.

The handler here stops *new* work from being pulled off the queue and lets the
current batch finish.  Messages that were never settled stay unacked and are
re-delivered by the broker, so nothing is lost by stopping mid-batch.
"""
import signal
import threading

_shutting_down = threading.Event()


def is_shutting_down() -> bool:
    """True once a termination signal has been received."""
    return _shutting_down.is_set()


def install_shutdown_handler(log, consumer, agent=None) -> None:
    """Handle SIGTERM/SIGINT by asking *consumer* to stop consuming.

    Registered per agent process.  Safe to call once per process; the handler
    itself only sets a flag and calls thread-safe consumer/producer teardown, so
    it does no real work inside the signal context.
    """

    def _handle(signum, _frame):
        name = signal.Signals(signum).name
        if _shutting_down.is_set():
            log.warning(f"{name} received again — already shutting down.")
            return
        _shutting_down.set()
        log.warning(
            f"{name} received — stopping consumption; the batch already in flight "
            f"will finish and anything unsettled will be re-delivered."
        )
        try:
            consumer.stop()
        except Exception as e:
            log.warning(f"Error while stopping the consumer: {e}")
        if agent is not None:
            producer = getattr(agent, "producer", None)
            if producer is not None:
                try:
                    producer.close()
                except Exception as e:
                    log.debug(f"Error closing the agent's producer: {e}")

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _handle)
        except ValueError:
            # Not the main thread of the process — nothing to install.
            log.debug(f"Could not install a handler for {sig!r} outside the main thread.")
