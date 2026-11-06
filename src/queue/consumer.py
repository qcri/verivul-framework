import json
import pika
import pika.exceptions
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List, Optional
from ..utils.logger import logger
from ..utils.queue import Outcome, RetryableError
from config.settings import settings
import time
from threading import Timer, RLock
import os


class QueueConsumer:
    def __init__(
        self,
        queue_name: str,
        # The callback receives a batch of messages.  It may return a list of
        # Outcome values (one per message, in order) to have them acknowledged
        # individually; returning None acknowledges the whole batch.
        callback: Callable[[List[Dict]], Optional[List[str]]],
        host: str = "localhost",
        port: int = 5672,
        max_retries: int = 3,
        batch_size: int = 1,
        batch_timeout: float = 1.0,
        max_workers: int = 1,
    ):
        self.log = logger.get_logger(f"consumer_{queue_name}")
        self.log.info(
            f"Initializing QueueConsumer for queue: {queue_name} "
            f"with batch_size={batch_size}, timeout={batch_timeout}s"
        )

        self.queue_name = queue_name

        self.callback = callback
        self.max_retries = settings.queues.get("max_retries", max_retries)
        self.host = os.getenv("RABBITMQ_HOST", host)
        self.port = int(os.getenv("RABBITMQ_PORT", port))
        self.user = os.getenv("RABBITMQ_USER")
        self.password = os.getenv("RABBITMQ_PASS")
        self.connection_attempts = settings.queues.get("connection_attempts", 5)
        self.retry_delay = settings.queues.get("connection_retry_delay", 5)

        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self._max_workers = max(1, max_workers)
        self._batch: List[Dict] = []
        self._delivery_tags: List[int] = []
        # Re-entrant: _on_message() holds this while calling _threadsafe_flush(),
        # whose connection-down fallback needs it again to re-arm the timer.
        self._lock = RLock()
        self._timer: Optional[Timer] = None
        # Set by stop(); makes the reconnect loop exit instead of coming back for
        # more work while the process is shutting down.
        self._stopping = False
        # Long enough for an in-flight ESBMC/compile container wait to return.
        self.shutdown_drain_seconds = float(
            settings.queues.get("shutdown_drain_seconds", 25)
        )

        # Run the user callback in a dedicated thread pool so the pika I/O loop
        # (and its heartbeat) are never blocked by long-running work (Docker
        # container waits, LLM API calls, etc.).
        self._executor = ThreadPoolExecutor(
            max_workers=self._max_workers, thread_name_prefix=f"cb_{self.queue_name}"
        )

        self.connection: Optional[pika.BlockingConnection] = None
        self.channel = None

        self._initialize_connection_with_retries()
        if self.connection and self.channel:
            self._declare_queue()
        else:
            self.log.error("Failed to establish initial connection after retries.")
            raise pika.exceptions.AMQPConnectionError(
                "Initial connection failed after retries"
            )

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _initialize_connection_with_retries(self):
        for attempt in range(self.connection_attempts):
            try:
                self._open_connection()
                self.log.info(f"Connected on attempt {attempt + 1}")
                return
            except pika.exceptions.AMQPConnectionError as e:
                self.log.warning(
                    f"Connection attempt {attempt + 1}/{self.connection_attempts} "
                    f"failed: {e}. Retrying in {self.retry_delay}s…"
                )
                if attempt < self.connection_attempts - 1:
                    time.sleep(self.retry_delay)
        self.log.error(f"All {self.connection_attempts} connection attempts failed.")
        self.connection = None
        self.channel = None
        raise pika.exceptions.AMQPConnectionError("All connection attempts exhausted")

    def _open_connection(self):
        """Open a fresh BlockingConnection and channel, closing any existing one first."""
        if self.connection and not self.connection.is_closed:
            try:
                self.connection.close()
            except Exception as e:
                self.log.debug(f"Error closing old connection: {e}")

        credentials = (
            pika.PlainCredentials(self.user, self.password)
            if self.user and self.password
            else None
        )
        if credentials:
            self.log.info(f"Using RabbitMQ credentials (user: {self.user})")

        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=self.host,
                port=self.port,
                credentials=credentials,
                # Heartbeat large enough to survive a full ESBMC verification run.
                # The callback runs in a worker thread so the I/O loop stays live,
                # but we keep a generous value as a safety net.
                heartbeat=600,
                blocked_connection_timeout=300,
            )
        )
        self.channel = self.connection.channel()
        self.log.info("RabbitMQ connection and channel established.")

    def _ensure_connection(self):
        """Reconnect if the connection or channel is gone."""
        if (
            not self.connection
            or self.connection.is_closed
            or not self.channel
            or self.channel.is_closed
        ):
            self.log.warning("Connection/channel lost — reconnecting.")
            self._initialize_connection_with_retries()
            self._declare_queue()

    def _declare_queue(self):
        """Idempotently declare the consumer's queue (no recursion)."""
        if not self.channel or self.channel.is_closed:
            self.log.error("Cannot declare queue — channel is not open.")
            return
        durable = settings.queues.get("durable", True)
        self.channel.queue_declare(queue=self.queue_name, durable=durable)
        self.log.info(f"Queue '{self.queue_name}' declared/ensured.")

    # ------------------------------------------------------------------
    # Batch management
    # ------------------------------------------------------------------

    def _schedule_flush(self):
        """Start the timeout timer if not already running (call with lock held)."""
        if self._timer is None and self.batch_timeout > 0:
            self._timer = Timer(self.batch_timeout, self._threadsafe_flush)
            self._timer.daemon = True
            self._timer.start()

    def _threadsafe_flush(self):
        """Safe to call from any thread — schedules _flush_batch on the I/O loop."""
        if self.connection and self.connection.is_open:
            try:
                self.connection.add_callback_threadsafe(self._flush_batch)
                return
            except Exception as e:
                self.log.warning(f"Could not schedule flush on the I/O loop: {e}")

        # The connection went away between the timer firing and this call.  The
        # batch must not be left with no timer armed — nothing would flush it
        # until batch_size more messages happened to arrive.
        with self._lock:
            if self._timer:
                self._timer.cancel()
                self._timer = None
            if self._batch:
                self.log.warning(
                    f"Flush skipped (connection down) with {len(self._batch)} message(s) "
                    f"buffered — re-arming the batch timer."
                )
                self._schedule_flush()

    def _flush_batch(self):
        """
        Called on the pika I/O thread.  Snapshots the current batch, clears it,
        then hands execution off to the worker thread via the executor so the
        I/O loop (and heartbeat) are not blocked.
        """
        with self._lock:
            if self._timer:
                self._timer.cancel()
                self._timer = None
            if not self._batch:
                return
            batch = self._batch[:]
            tags = self._delivery_tags[:]
            self._batch.clear()
            self._delivery_tags.clear()

        # Snapshot connection/channel for use inside the done-callback closure.
        conn_snap = self.connection
        chan_snap = self.channel

        self.log.info(f"Dispatching batch of {len(batch)} messages to worker thread.")
        future = self._executor.submit(self.callback, batch)
        future.add_done_callback(
            lambda f: self._on_batch_done(f, tags, conn_snap, chan_snap)
        )

    def _resolve_outcomes(self, future, count: int) -> List[str]:
        """Turn the callback's result (or exception) into one Outcome per message."""
        exc = future.exception()

        if exc is None:
            result = future.result()
            # A callback may return a per-message outcome list so one bad message
            # no longer decides the fate of its whole batch.  Anything else (the
            # historical contract) means "the batch as a whole is done".
            if isinstance(result, (list, tuple)) and len(result) == count and all(
                r in (Outcome.ACK, Outcome.RETRY, Outcome.DROP) for r in result
            ):
                retried = sum(1 for r in result if r == Outcome.RETRY)
                dropped = sum(1 for r in result if r == Outcome.DROP)
                self.log.info(
                    f"Batch of {count} settled per-message: "
                    f"{count - retried - dropped} ack, {retried} retry, {dropped} drop."
                )
                return list(result)
            if isinstance(result, (list, tuple)) and result:
                self.log.warning(
                    f"Callback returned {len(result)} outcome(s) for a batch of {count}, "
                    f"or used unknown values — ACKing the whole batch instead."
                )
            self.log.info(f"Batch succeeded — ACKing {count} messages.")
            return [Outcome.ACK] * count

        if isinstance(exc, RetryableError):
            # Transient infrastructure failure (DB pool exhausted, Docker API
            # blip, no free slot, …).  Requeue so the broker re-delivers once the
            # condition clears.  The agent's internal retries already ran, so
            # re-delivery happens after a full round-trip through the queue.
            self.log.warning(
                f"Batch raised RetryableError — NACKing {count} messages "
                f"with requeue=True. Error: {exc}",
            )
            return [Outcome.RETRY] * count

        self.log.error(
            f"Batch callback raised an exception — NACKing {count} messages "
            f"(no requeue to avoid an infinite loop; rely on the resume path). Error: {exc}",
            exc_info=exc,
        )
        return [Outcome.DROP] * count

    def _on_batch_done(self, future, tags, conn, chan):
        """
        Called from the worker thread when the callback finishes.
        Schedules ACK or NACK back onto the pika I/O loop so channel
        operations happen on the correct thread.
        """
        outcomes = self._resolve_outcomes(future, len(tags))

        def _settle():
            for tag, outcome in zip(tags, outcomes):
                if not (chan and chan.is_open):
                    # Unacked messages are re-delivered as soon as the connection
                    # drops, so abandoning the rest here loses nothing.
                    self.log.warning(
                        "Channel closed while settling a batch — the remaining messages "
                        "will be re-delivered by the broker."
                    )
                    return
                if outcome == Outcome.ACK:
                    chan.basic_ack(delivery_tag=tag)
                else:
                    chan.basic_nack(delivery_tag=tag, requeue=(outcome == Outcome.RETRY))

        if conn and conn.is_open:
            try:
                conn.add_callback_threadsafe(_settle)
            except Exception as e:
                self.log.warning(f"Could not schedule ACK/NACK (connection gone): {e}")

    # ------------------------------------------------------------------
    # Message handler (called on pika I/O thread)
    # ------------------------------------------------------------------

    def _on_message(self, ch, method, properties, body):
        with self._lock:
            try:
                message = json.loads(body)
            except json.JSONDecodeError:
                self.log.error(f"Invalid JSON — rejecting message: {body[:200]}")
                if ch.is_open:
                    ch.basic_reject(delivery_tag=method.delivery_tag, requeue=False)
                return

            self._batch.append(message)
            self._delivery_tags.append(method.delivery_tag)

            # Arm the timer whenever the buffer is non-empty and unarmed, not only
            # on the first message: if a flush was ever skipped the batch would
            # otherwise sit there until batch_size more messages happened to arrive.
            if self._batch:
                self._schedule_flush()

            if len(self._batch) >= self.batch_size:
                self._threadsafe_flush()

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def start_consuming(self):
        while not self._stopping:
            try:
                self._ensure_connection()
                if not self.channel or self.channel.is_closed:
                    self.log.error("Channel not open — retrying…")
                    time.sleep(self.retry_delay)
                    continue

                prefetch = self.batch_size * self._max_workers
                self.channel.basic_qos(prefetch_count=prefetch)
                self.channel.basic_consume(
                    queue=self.queue_name,
                    on_message_callback=self._on_message,
                    auto_ack=False,
                )
                self.log.info(
                    f"Consuming '{self.queue_name}' (prefetch={prefetch})."
                )
                self.channel.start_consuming()

            except pika.exceptions.StreamLostError as e:
                self.log.error(f"StreamLostError: {e} — reconnecting…")
            except pika.exceptions.AMQPConnectionError as e:
                self.log.error(f"AMQPConnectionError: {e} — reconnecting…")
            except KeyboardInterrupt:
                self.log.info("Shutdown signal received.")
                break
            except Exception as e:
                self.log.error(f"Unexpected error in consumer loop: {e}", exc_info=True)
            finally:
                self._close_connection()

            if self._stopping:
                break
            self.log.info(f"Waiting {self.retry_delay}s before reconnecting…")
            time.sleep(self.retry_delay)

        if self._stopping:
            self._drain(timeout=self.shutdown_drain_seconds)

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def stop(self):
        """Stop pulling new messages; safe to call from a signal handler.

        Only sets a flag and schedules ``stop_consuming`` onto the pika I/O
        thread, so it does no blocking work in the signal context.  Whatever is
        already running finishes in _drain(); messages that were never settled
        remain unacked and the broker re-delivers them.
        """
        self._stopping = True
        if self.connection and self.connection.is_open:
            try:
                self.connection.add_callback_threadsafe(self._stop_consuming_on_io_thread)
                return
            except Exception as e:
                self.log.debug(f"Could not schedule stop_consuming: {e}")
        # No usable connection: the main loop will notice _stopping and exit.

    def _stop_consuming_on_io_thread(self):
        try:
            if self.channel and self.channel.is_open:
                self.channel.stop_consuming()
        except Exception as e:
            self.log.debug(f"stop_consuming failed: {e}")

    def _drain(self, timeout: float):
        """Wait for in-flight callbacks to finish before the process exits."""
        self.log.info(f"Draining in-flight work (up to {timeout:.0f}s)…")
        with self._lock:
            if self._timer:
                self._timer.cancel()
                self._timer = None
            buffered = len(self._batch)
        if buffered:
            self.log.warning(
                f"{buffered} buffered message(s) were never dispatched — they stay "
                f"unacked and will be re-delivered."
            )
        # wait=True blocks until running callbacks return; queued-but-unstarted
        # work is dropped, and those messages are unacked so nothing is lost.
        self._executor.shutdown(wait=True, cancel_futures=True)
        self.log.info("Drain complete.")

    def _close_connection(self):
        """Close channel and connection without raising."""
        try:
            if self.channel and self.channel.is_open:
                self.channel.close()
        except Exception as e:
            self.log.debug(f"Error closing channel: {e}")
        try:
            if self.connection and not self.connection.is_closed:
                self.connection.close()
        except Exception as e:
            self.log.debug(f"Error closing connection: {e}")
        finally:
            self.channel = None
            self.connection = None

    def close(self):
        self.log.info("Closing consumer.")
        # Cancel any pending flush timer so its thread doesn't outlive the process.
        with self._lock:
            if self._timer:
                self._timer.cancel()
                self._timer = None
        self._executor.shutdown(wait=False)
        self._close_connection()
