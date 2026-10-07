"""
Structured application logging.

Log lines use ``key=value`` pairs after the message so they are both human
readable and easy to grep/parse.  A redaction filter scrubs anything that
looks like a Groq API key, as a defence-in-depth measure.
"""

from __future__ import annotations

import logging
import re
import sys

_SECRET_PATTERNS = [
    re.compile(r"gsk_[A-Za-z0-9]{8,}"),            # Groq keys
    re.compile(r"(postgresql(?:\+\w+)?://[^:/]+:)[^@]+(@)"),  # DB passwords in URLs
]


class RedactSecretsFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        redacted = msg
        for pattern in _SECRET_PATTERNS:
            if pattern.groups == 2:
                redacted = pattern.sub(r"\1***\2", redacted)
            else:
                redacted = pattern.sub("***REDACTED***", redacted)
        if redacted != msg:
            record.msg = redacted
            record.args = ()
        return True


def kv(**fields) -> str:
    """Render keyword fields as ``key=value`` pairs for structured log lines."""
    return " ".join(f"{k}={v}" for k, v in fields.items())


_configured = False


def configure_logging(level: str = "INFO") -> None:
    global _configured
    if _configured:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("%(asctime)s level=%(levelname)s logger=%(name)s msg=%(message)s")
    )
    handler.addFilter(RedactSecretsFilter())
    root = logging.getLogger("app")
    root.setLevel(level.upper())
    root.addHandler(handler)
    root.propagate = True
    _configured = True


def redact(text: str) -> str:
    """Utility used by tests and error handlers."""
    rec = logging.LogRecord("x", logging.INFO, "", 0, text, (), None)
    RedactSecretsFilter().filter(rec)
    return rec.getMessage()
