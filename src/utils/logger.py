import logging
import logging.handlers
import multiprocessing
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

class MultiProcessLogger:
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MultiProcessLogger, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self._initialized = True
            self.log_dir = Path("logs")
            self.log_dir.mkdir(exist_ok=True)
            
            self.setup_logging()

    def warning(self, *args, **kwargs):
        self.get_logger().warning(*args, **kwargs)

    def error(self, *args, **kwargs):
        self.get_logger().error(*args, **kwargs)

    def info(self, *args, **kwargs):
        self.get_logger().info(*args, **kwargs)

    def debug(self, *args, **kwargs):
        self.get_logger().debug(*args, **kwargs)

    def setup_logging(self):
        root_logger = logging.getLogger()
        # Guard against adding duplicate handlers — important when this module is
        # imported multiple times or when child processes are spawned (not forked).
        if root_logger.handlers:
            return

        root_logger.setLevel(logging.INFO)

        timestamp = datetime.now().strftime("%Y%m%d")
        log_file = self.log_dir / f"verification_system_{timestamp}.log"

        formatter = logging.Formatter(
            '%(asctime)s - %(processName)s - %(name)s - %(levelname)s - %(message)s'
        )

        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10485760,
            backupCount=5,
        )
        file_handler.setFormatter(formatter)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)

    def get_logger(self, name: Optional[str] = None) -> logging.Logger:
        logger_name = name if name else multiprocessing.current_process().name
        return logging.getLogger(logger_name)

logger = MultiProcessLogger()
