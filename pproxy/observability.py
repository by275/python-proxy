"""Opt-in structured logging helpers.

The CLI's existing verbose callback remains unchanged. Applications that need
machine-readable records can configure this logger explicitly.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import TextIO


class JsonFormatter(logging.Formatter):
    """Render a log record as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            'time': self.formatTime(record, datefmt='%Y-%m-%dT%H:%M:%S%z'),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        if record.exc_info:
            payload['exception'] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, separators=(',', ':'))


def configure_logging(
    level: int = logging.INFO,
    *,
    structured: bool = False,
    stream: TextIO | None = None,
) -> logging.Logger:
    """Configure and return the opt-in ``pproxy`` logger.

    This helper does not alter the legacy verbose output path. Calling it is
    an explicit application-level choice.
    """
    logger = logging.getLogger('pproxy')
    logger.handlers.clear()
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter() if structured else logging.Formatter('%(message)s'))
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger
