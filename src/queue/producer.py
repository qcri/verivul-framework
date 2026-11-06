import json
import os
import threading
import time
from typing import Any, Dict, Optional

import pika
import pika.exceptions

from config.settings import settings
from ..utils.logger import logger
from ..utils.queue import PublishError


# pika exceptions that mean "this connection/channel is unusable, reconnect and
# retry".  ChannelWrongStateError and the AssertionError/IndexError pair show up
# when a BlockingConnection's internal transmit buffer has been corrupted.
_TRANSIENT_ERRORS = (
    pika.exceptions.AMQPConnectionError,
    pika.exceptions.AMQPChannelError,      # covers ChannelClosedByBroker, ChannelWrongStateError
    pika.exceptions.StreamLostError,
    pika.exceptions.NackError,             # broker explicitly refused the message
    pika.exceptions.UnroutableError,       # no queue accepted it
    AssertionError,                        # pika internal transport-state assertions
    IndexError,                            # pika _produce() popping an empty tx deque
    OSError,                               # socket-level failures
)


class QueueProducer:
    """Thread-safe RabbitMQ publisher.

    pika's BlockingConnection is explicitly **not** thread-safe, and a single
    QueueProducer instance is shared by every worker thread of an agent's
    consumer pool (``*_concurrency`` in config).  Concurrent use corrupts the
    AMQP frame stream, which surfaces as transmit-buffer assertions, "pop from
    an empty deque", or a silently aborted connection — and the messages
    involved are lost while the caller believes they were sent.

    Every connection and channel operation therefore happens under ``_lock``.
    Publishing is a single frame write plus one confirm round-trip (sub-
    millisecond against a local broker), while the work between publishes takes
    seconds, so serialising publishes costs nothing measurable and is far safer
    than juggling one connection per thread.

    Publisher confirms are enabled, so a successful ``publish_message`` means
    the broker has accepted and persisted the message — not merely that a write
    to a socket buffer returned.
    """

    def __init__(self, caller: str, host: str = "localhost", port: int = 5672):
        self.log = logger.get_logger(f"queue_producer_{caller}")
        self.log.info("Initializing QueueProducer")

        self.host = os.getenv("RABBITMQ_HOST", host)
        self.port = int(os.getenv("RABBITMQ_PORT", port))
        self.user = os.getenv("RABBITMQ_USER")
        self.password = os.getenv("RABBITMQ_PASS")
        self.durable = settings.queues.get("durable", True)

        # Re-entrant: publish_message() holds the lock while calling
        # _ensure_connection(), which may call _connect_with_retries().
        self._lock = threading.RLock()
        self.connection: Optional[pika.BlockingConnection] = None
        self.channel = None
        # Queues already declared on the current channel.  Declaring is an RPC
        # round-trip; doing it on every publish (as this class used to) triples
        # the broker traffic and holds the lock far longer than necessary.
        self._declared: set = set()

        self._connect_with_retries(caller="init")
        self.log.info("QueueProducer initialised successfully.")

    # ------------------------------------------------------------------
    # Connection management — all callers must hold self._lock
    # ------------------------------------------------------------------

    def _connect_with_retries(self, caller: str, max_attempts: int = 5, base_delay: float = 2.0):
        with self._lock:
            for attempt in range(max_attempts):
                try:
                    self._connect()
                    return
                except pika.exceptions.AMQPConnectionError as e:
                    if attempt < max_attempts - 1:
                        delay = base_delay * (2 ** attempt)
                        self.log.warning(
                            f"[{caller}] Connection attempt {attempt + 1}/{max_attempts} "
                            f"failed: {e}. Retrying in {delay:.1f}s…"
                        )
                        time.sleep(delay)
                    else:
                        self.log.error(
                            f"[{caller}] All {max_attempts} connection attempts failed."
                        )
                        raise

    def _connect(self):
        """Open a fresh connection and channel, closing any existing one first."""
        self._close_quietly()

        if self.user and self.password:
            credentials = pika.PlainCredentials(self.user, self.password)
            self.log.info(f"Using RabbitMQ credentials (user: {self.user})")
        else:
            # Passing credentials=None to ConnectionParameters raises TypeError;
            # fall back to the broker default (matches docker-compose's guest/guest).
            credentials = pika.PlainCredentials("guest", "guest")
            self.log.warning(
                "RABBITMQ_USER/RABBITMQ_PASS not set; using default guest credentials"
            )

        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=self.host,
                port=self.port,
                credentials=credentials,
                heartbeat=600,
                blocked_connection_timeout=300,
            )
        )
        self.channel = self.connection.channel()
        # Turn basic_publish into a synchronous, verified operation: it now
        # raises NackError/UnroutableError instead of failing silently.
        self.channel.confirm_delivery()
        self._declared.clear()
        self.log.info("RabbitMQ connection and channel established (publisher confirms on).")

    def _close_quietly(self):
        """Tear down the current channel/connection without raising."""
        try:
            if self.channel and self.channel.is_open:
                self.channel.close()
        except Exception as e:
            self.log.debug(f"Error closing old channel: {e}")
        try:
            if self.connection and not self.connection.is_closed:
                self.connection.close()
        except Exception as e:
            self.log.debug(f"Error closing old connection: {e}")
        finally:
            self.channel = None
            self.connection = None
            self._declared.clear()

    def _ensure_connection(self):
        """Reconnect with retries if the connection or channel is gone."""
        if (
            not self.connection
            or self.connection.is_closed
            or not self.channel
            or self.channel.is_closed
        ):
            self.log.warning("Connection/channel lost — reconnecting.")
            self._connect_with_retries(caller="ensure_connection")

    def _declare_once(self, queue: str):
        """Declare *queue* unless it has already been declared on this channel.

        RabbitMQ silently drops messages published to a non-existent queue with
        mandatory=False, so the queue must exist before the first publish.
        """
        if queue not in self._declared:
            self.channel.queue_declare(queue=queue, durable=self.durable)
            self._declared.add(queue)

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    def publish_message(
        self,
        queue: str,
        message: Dict[str, Any],
        max_retries: int = 3,
    ) -> bool:
        """Publish *message* to *queue*, returning True only once the broker confirms it.

        Never raises.  Callers that must not lose the message should use
        :meth:`publish_or_raise` instead of testing the return value, so a
        forgotten check cannot turn into a silently stranded snippet.
        """
        message_id = message.get("uuid", "N/A")
        body = json.dumps(message)

        with self._lock:
            for attempt in range(max_retries + 1):
                try:
                    self._ensure_connection()
                    self._declare_once(queue)
                    self.channel.basic_publish(
                        exchange="",
                        routing_key=queue,
                        body=body,
                        properties=pika.BasicProperties(
                            delivery_mode=2,  # persistent
                            message_id=message_id,
                        ),
                        mandatory=True,  # with confirms, guarantees the queue took it
                    )
                    self.log.info(f"Published {message_id} → {queue}")
                    return True

                except _TRANSIENT_ERRORS as e:
                    # The connection may be in an unknown state — drop it so the
                    # next attempt builds a clean one rather than reusing a
                    # half-corrupted transmit buffer.
                    self._close_quietly()
                    if attempt < max_retries:
                        delay = 2 ** attempt  # 1 s, 2 s, 4 s …
                        self.log.warning(
                            f"Publish failed for {message_id} → {queue} "
                            f"(attempt {attempt + 1}/{max_retries + 1}): "
                            f"{type(e).__name__}: {e}. Retrying in {delay}s…"
                        )
                        time.sleep(delay)
                    else:
                        self.log.error(
                            f"Giving up publishing {message_id} → {queue} after "
                            f"{max_retries + 1} attempts: {type(e).__name__}: {e}"
                        )
                        return False

                except Exception as e:
                    self.log.error(
                        f"Unexpected error publishing {message_id} → {queue}: {e}",
                        exc_info=True,
                    )
                    self._close_quietly()
                    return False

        return False  # unreachable, satisfies type checkers

    def publish_or_raise(
        self,
        queue: str,
        message: Dict[str, Any],
        max_retries: int = 3,
    ) -> None:
        """Publish *message*, raising :class:`PublishError` if the broker never confirmed it."""
        if not self.publish_message(queue, message, max_retries=max_retries):
            raise PublishError(
                f"Could not publish {message.get('uuid', 'N/A')} to '{queue}' "
                f"after {max_retries + 1} attempts"
            )

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def close(self):
        self.log.info("Closing producer connection.")
        with self._lock:
            try:
                self._close_quietly()
                self.log.info("Producer connection closed.")
            except Exception as e:
                self.log.error(f"Error closing producer connection: {e}", exc_info=True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        if exc_val:
            self.log.error(
                f"QueueProducer context exited with error: {exc_val}",
                exc_info=(exc_type, exc_val, exc_tb),
            )
