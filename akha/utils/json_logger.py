"""Structured JSON logging helpers."""

from __future__ import annotations

import json
import logging
import time
from contextvars import ContextVar
from typing import Any, Dict

_scan_id: ContextVar[str] = ContextVar("scan_id", default="")
_target_id: ContextVar[str] = ContextVar("target_id", default="")
_worker_id: ContextVar[str] = ContextVar("worker_id", default="")
_request_id: ContextVar[str] = ContextVar("request_id", default="")
_payload_id: ContextVar[str] = ContextVar("payload_id", default="")
_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")
_proxy_id: ContextVar[str] = ContextVar("proxy_id", default="")


def bind_log_context(**kwargs: str) -> None:
    if "scan_id" in kwargs:
        _scan_id.set(kwargs.get("scan_id") or "")
    if "target_id" in kwargs:
        _target_id.set(kwargs.get("target_id") or "")
    if "worker_id" in kwargs:
        _worker_id.set(kwargs.get("worker_id") or "")
    if "request_id" in kwargs:
        _request_id.set(kwargs.get("request_id") or "")
    if "payload_id" in kwargs:
        _payload_id.set(kwargs.get("payload_id") or "")
    if "correlation_id" in kwargs:
        _correlation_id.set(kwargs.get("correlation_id") or "")
    if "proxy_id" in kwargs:
        _proxy_id.set(kwargs.get("proxy_id") or "")


def get_log_context() -> Dict[str, str]:
    return {
        "scan_id": _scan_id.get(),
        "target_id": _target_id.get(),
        "worker_id": _worker_id.get(),
        "request_id": _request_id.get(),
        "payload_id": _payload_id.get(),
        "correlation_id": _correlation_id.get(),
        "proxy_id": _proxy_id.get(),
    }


class ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.scan_id = _scan_id.get()
        record.target_id = _target_id.get()
        record.worker_id = _worker_id.get()
        record.request_id = _request_id.get()
        record.payload_id = _payload_id.get()
        record.correlation_id = _correlation_id.get()
        record.proxy_id = _proxy_id.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "scan_id": getattr(record, "scan_id", ""),
            "target_id": getattr(record, "target_id", ""),
            "worker_id": getattr(record, "worker_id", ""),
            "request_id": getattr(record, "request_id", ""),
            "payload_id": getattr(record, "payload_id", ""),
            "correlation_id": getattr(record, "correlation_id", ""),
            "proxy_id": getattr(record, "proxy_id", ""),
        }
        if record.exc_info:
            payload["error"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True)


def setup_json_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(ContextFilter())

    root.handlers = [handler]
