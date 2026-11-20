"""
SENTRIX Log Watcher
-------------------
Tails local log files and extracts structured events from new lines.
Recognised event types:
  - error          (application errors, exceptions, crashes)
  - failed_login   (authentication failures)
  - slow_response  (requests exceeding a latency threshold)

The watcher remembers its read position so it only processes new lines
on each call.  This means you can call poll() in a loop and each call
returns only the events from lines appended since the last call.
"""

import os
import re
from dataclasses import dataclass
from typing import List, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class LogEvent:
    """A structured event extracted from a raw log line."""
    timestamp: str            # e.g. "2026-11-20 14:30:05"
    event_type: str           # 'error' | 'failed_login' | 'slow_response'
    message: str              # the raw message text (redacted before sending)
    source_file: str          # basename of the source log file
    severity: str = 'warning' # 'info' | 'warning' | 'critical'


# ---------------------------------------------------------------------------
# Line-parsing patterns
# ---------------------------------------------------------------------------

# Matches structured log lines like:
#   2026-11-20 14:30:05 ERROR [web-server] Database connection timeout...
_LOG_LINE_RE = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<level>ERROR|WARN|CRITICAL|FATAL)\s+'
    r'(?:\[(?P<component>[^\]]+)\]\s+)?'
    r'(?P<msg>.+)'
)

# Sub-patterns used to classify the event type
_FAILED_LOGIN_RE = re.compile(
    r'(?i)failed\s+(login|auth|sign[\s\-]?in|authentication)'
)
_SLOW_RESPONSE_RE = re.compile(
    r'(?i)(slow\s+response|high\s+latency|took\s+\d+\s*ms|timeout|timed?\s*out)'
)


# ---------------------------------------------------------------------------
# LogWatcher class
# ---------------------------------------------------------------------------

class LogWatcher:
    """
    Watch one or more log files for new lines and extract events.

    Usage::

        watcher = LogWatcher(['/var/log/app.log', '/var/log/auth.log'])
        new_events = watcher.poll()   # returns events from new lines only
    """

    def __init__(self, paths: List[str]):
        self._paths = paths
        # Track the byte offset we've read up to in each file
        self._offsets: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def poll(self) -> List[LogEvent]:
        """Read new lines from all watched files and return extracted events."""
        events: List[LogEvent] = []
        for path in self._paths:
            if not os.path.exists(path):
                continue
            events.extend(self._read_new_lines(path))
        return events

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_new_lines(self, path: str) -> List[LogEvent]:
        """Read from saved offset to end-of-file; return parsed events."""
        events: List[LogEvent] = []
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                # Seek to where we left off (0 if first read)
                f.seek(self._offsets.get(path, 0))
                for line in f:
                    line = line.strip()
                    if line:
                        event = self._parse_line(line, path)
                        if event is not None:
                            events.append(event)
                # Remember position for next poll
                self._offsets[path] = f.tell()
        except (IOError, OSError):
            pass  # file may be temporarily unavailable; skip this cycle
        return events

    def _parse_line(self, line: str, source: str) -> Optional[LogEvent]:
        """
        Try to extract a structured event from a single log line.
        Returns None if the line is not a recognised error/warning.
        """
        m = _LOG_LINE_RE.match(line)
        if not m:
            return None

        ts = m.group('ts')
        level = m.group('level')
        msg = m.group('msg')
        fname = os.path.basename(source)
        is_critical = level in ('CRITICAL', 'FATAL')

        # Classify: failed login takes priority, then slow response, then
        # generic error.
        if _FAILED_LOGIN_RE.search(msg):
            return LogEvent(
                timestamp=ts,
                event_type='failed_login',
                message=msg,
                source_file=fname,
                severity='critical' if is_critical else 'warning',
            )

        if _SLOW_RESPONSE_RE.search(msg):
            return LogEvent(
                timestamp=ts,
                event_type='slow_response',
                message=msg,
                source_file=fname,
                severity='warning',
            )

        if level in ('ERROR', 'CRITICAL', 'FATAL'):
            return LogEvent(
                timestamp=ts,
                event_type='error',
                message=msg,
                source_file=fname,
                severity='critical' if is_critical else 'warning',
            )

        # WARN lines that don't match a specific category are ignored
        return None
