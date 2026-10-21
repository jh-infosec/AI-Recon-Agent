"""
logtime.py
==========
Turn the timestamp on a log line into a point in time that lines from other
logs can be sorted against.

A hunt reads several logs from one box, and the formats disagree about almost
everything:

  classic syslog   Oct 14 10:02:11 web sshd[812]: ...
                   No year and no timezone. Still what older distributions,
                   and this project's sample logs, write.
  rsyslog ISO      2026-10-14T10:02:11.123456+02:00 web sshd[812]: ...
                   Full date and offset. The default on Debian 12 and recent
                   Ubuntu, so the likeliest shape on a homelab VM.
  Apache / nginx   ... [14/Oct/2026:10:03:40 +0200] "GET / ..."
                   Full date and offset, mid-line.
  JSON lines       {"timestamp": "2026-10-14T08:03:40Z", ...}
                   Any of a handful of field names, ISO text or epoch number.

Every result is UTC. A timestamp that carries its own offset is converted
exactly. One that does not (classic syslog, a bare ISO time) is given an
offset, and the choice is reported rather than hidden: the logs of one box
share a clock, so if any of its logs state their offset, that offset is the
best guess for the ones that do not; with nothing to go on, UTC is assumed and
said to be assumed. The same reasoning supplies classic syslog's missing year.
"""

import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

_ISO_AT_START = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)(?=\s|$)")
_SYSLOG_AT_START = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\b")
_CLF = re.compile(
    r"\[(?P<day>\d{2})/(?P<mon>[A-Z][a-z]{2})/(?P<year>\d{4}):(?P<h>\d{2}):(?P<m>\d{2}):"
    r"(?P<s>\d{2}) (?P<off>[+-]\d{4})\]")
_JSON_TIME_KEYS = ("timestamp", "@timestamp", "time", "ts", "datetime", "UtcTime",
                   "TimeCreated", "eventTime", "date")

# Epoch values outside this window are not timestamps (a PID, a port, a size).
_EPOCH_MIN, _EPOCH_MAX = 946_684_800, 4_102_444_800        # 2000 to 2100


def _iso(text: str):
    """fromisoformat, made to accept 'Z', '+0200' and over-long fractions."""
    t = text.strip().replace(" ", "T", 1)
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    t = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", t)
    t = re.sub(r"(\.\d{6})\d+", r"\1", t)
    try:
        return datetime.fromisoformat(t)
    except ValueError:
        return None


def _epoch(value):
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if v > _EPOCH_MAX * 1000:          # microseconds? not a format we see
        return None
    if v > _EPOCH_MAX:                 # milliseconds
        v /= 1000.0
    if not _EPOCH_MIN <= v <= _EPOCH_MAX:
        return None
    return datetime.fromtimestamp(v, tz=timezone.utc)


def parse_line(line: str):
    """
    The raw timestamp on one line, or None.

    Returns (kind, value) where kind is "aware" (a datetime with its offset),
    "naive" (a datetime with no offset) or "syslog" (a (month, day, h, m, s)
    tuple with no year and no offset). Resolution to UTC happens later, once
    the whole workspace has been seen.
    """
    if not line:
        return None
    s = line.lstrip()
    if s.startswith("{"):
        try:
            obj = json.loads(s)
        except (json.JSONDecodeError, ValueError):
            obj = None
        if isinstance(obj, dict):
            for key in _JSON_TIME_KEYS:
                if key in obj:
                    v = obj[key]
                    dt = _epoch(v) if isinstance(v, (int, float)) else _iso(str(v))
                    if dt is not None:
                        return ("aware" if dt.tzinfo else "naive", dt)
            return None
    m = _ISO_AT_START.match(s)
    if m:
        dt = _iso(m.group("ts"))
        if dt is not None:
            return ("aware" if dt.tzinfo else "naive", dt)
    m = _SYSLOG_AT_START.match(s)
    if m and m.group("mon") in _MONTHS:
        return ("syslog", (_MONTHS[m.group("mon")], int(m.group("day")),
                           int(m.group("h")), int(m.group("m")), int(m.group("s"))))
    m = _CLF.search(s)
    if m and m.group("mon") in _MONTHS:
        off = m.group("off")
        sign = 1 if off[0] == "+" else -1
        tz = timezone(sign * timedelta(hours=int(off[1:3]), minutes=int(off[3:5])))
        try:
            dt = datetime(int(m.group("year")), _MONTHS[m.group("mon")], int(m.group("day")),
                          int(m.group("h")), int(m.group("m")), int(m.group("s")), tzinfo=tz)
        except ValueError:
            return None
        return ("aware", dt)
    return None


class Clock:
    """
    What the workspace's own logs say about its clock: the offset they state,
    and the year. Built from every aware timestamp seen, then used to place
    the ones that state neither.
    """

    def __init__(self, fallback_year: int):
        self.offsets: Counter = Counter()
        self.latest = None
        self.fallback_year = fallback_year

    def observe(self, parsed) -> None:
        if parsed and parsed[0] == "aware":
            dt = parsed[1]
            self.offsets[dt.utcoffset()] += 1
            if self.latest is None or dt > self.latest:
                self.latest = dt

    @property
    def offset(self):
        """The offset the box's logs most often state, or None."""
        return self.offsets.most_common(1)[0][0] if self.offsets else None

    @property
    def year(self) -> int:
        return self.latest.year if self.latest else self.fallback_year

    def note(self) -> str:
        if self.offset is None:
            return ("no log states its timezone; times without an offset are "
                    "assumed to be UTC")
        hours = self.offset.total_seconds() / 3600
        extra = (f" ({len(self.offsets)} different offsets seen; the most common "
                 f"was used)" if len(self.offsets) > 1 else "")
        return (f"times without an offset are assumed to share the offset the other "
                f"logs state, UTC{hours:+g}{extra}")


def syslog_years(months: list, year: int) -> list:
    """
    A year for each classic-syslog line, given their months in file order.

    The file is append-ordered, so a month going backwards means the log
    crossed into a new year. The LAST line is placed in `year`, and earlier
    lines step back one year per crossing.
    """
    crossings, prev, marks = 0, None, []
    for mon in months:
        if prev is not None and mon is not None and mon < prev:
            crossings += 1
        if mon is not None:
            prev = mon
        marks.append(crossings)
    return [year - (crossings - k) for k in marks]


def to_utc(parsed, clock: Clock, year: int | None = None):
    """Resolve one parse_line result to an aware UTC datetime, or None."""
    if not parsed:
        return None
    kind, value = parsed
    if kind == "aware":
        return value.astimezone(timezone.utc)
    tz = timezone(clock.offset) if clock.offset is not None else timezone.utc
    if kind == "naive":
        return value.replace(tzinfo=tz).astimezone(timezone.utc)
    mon, day, h, m, s = value
    try:
        local = datetime(year or clock.year, mon, day, h, m, s, tzinfo=tz)
    except ValueError:              # 29 Feb in a guessed non-leap year
        return None
    return local.astimezone(timezone.utc)


def parse_bound(text: str):
    """A start or end bound from the model: ISO text, read as UTC if no offset."""
    if not text or not str(text).strip():
        return None
    dt = _iso(str(text))
    if dt is None:
        raise ValueError(f"not an ISO 8601 time: {text!r}")
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
