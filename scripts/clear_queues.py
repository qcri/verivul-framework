#!/usr/bin/env python3
"""
clear_queues.py — Purge all RabbitMQ queues using credentials from .env.

Usage:
    python scripts/clear_queues.py
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from src.utils.queue import clear_rabbitmq_queues
from src.utils.logger import logger

log = logger.get_logger("clear_queues")

if __name__ == "__main__":
    log.info(
        f"Connecting to RabbitMQ at "
        f"{os.getenv('RABBITMQ_HOST', 'localhost')}:{os.getenv('RABBITMQ_PORT', 5672)}"
    )
    clear_rabbitmq_queues()
    log.info("Done.")
