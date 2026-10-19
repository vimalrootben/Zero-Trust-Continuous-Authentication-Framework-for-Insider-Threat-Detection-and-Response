"""Bounded, crash-safe JSON-lines operational logging for the endpoint agent."""

import json
import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path


class UTCJsonFormatter(logging.Formatter):
    """Machine-readable formatter with a deliberately small, non-secret schema."""

    _fields = ("event_name", "event_type", "agent_id", "event_id", "command_id",
               "correlation_id", "request_id", "error_code", "error_type")

    def format(self, record):
        item = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "component": record.name[:128],
            "event_name": str(getattr(record, "event_name", None) or
                              getattr(record, "event_type", None) or record.msg)[:128],
            "message": record.getMessage()[:4096],
        }
        for name in self._fields:
            value = getattr(record, name, None)
            if value is not None:
                item[name] = str(value)[:512]
        if record.exc_info:
            item["exception"] = self.formatException(record.exc_info)[:8192]
        return json.dumps(item, ensure_ascii=False, default=str)


def configure_agent_logging(log_path=None):
    """Install one rotating local handler; storage failure leaves stderr logging usable."""
    target = Path(log_path or os.environ.get("ZTA_AGENT_LOG_PATH", "logs/zta-agent.jsonl"))
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            target, maxBytes=max(64 * 1024, int(os.environ.get("ZTA_AGENT_LOG_MAX_BYTES", "5242880"))),
            backupCount=max(1, min(100, int(os.environ.get("ZTA_AGENT_LOG_BACKUPS", "5")))),
            encoding="utf-8", delay=True,
        )
        handler.setFormatter(UTCJsonFormatter())
        root = logging.getLogger()
        if not any(getattr(existing, "baseFilename", None) == handler.baseFilename for existing in root.handlers):
            root.addHandler(handler)
        root.setLevel(getattr(logging, os.environ.get("ZTA_LOG_LEVEL", "INFO").upper(), logging.INFO))
        return target
    except (OSError, ValueError):
        logging.getLogger(__name__).exception("agent.log_storage_unavailable")
        return None
