from dataclasses import asdict, dataclass
from pathlib import Path
import json
import os
import time
import uuid


DEFAULT_EVENT_LOG_PATH = os.getenv("PANEL_EVENT_LOG_PATH", "/app/data/events.jsonl")


@dataclass(frozen=True)
class Event:
    id: str
    ts: float
    source: str
    level: str
    action: str
    message: str
    details: dict[str, object]


class EventLog:
    def __init__(self, path: str = DEFAULT_EVENT_LOG_PATH) -> None:
        self.path = Path(path)

    def append(
        self,
        *,
        source: str,
        action: str,
        message: str,
        level: str = "info",
        details: dict[str, object] | None = None,
    ) -> Event:
        event = Event(
            id=uuid.uuid4().hex,
            ts=time.time(),
            source=source,
            level=level,
            action=action,
            message=message,
            details=details or {},
        )
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(asdict(event), separators=(",", ":")) + "\n")
        except OSError:
            pass
        return event

    def tail(self, limit: int = 100) -> list[dict[str, object]]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()[-limit:]
        events: list[dict[str, object]] = []
        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                events.append(event)
        return events

    def filter(self, *, limit: int = 100, level: str = "", source: str = "") -> list[dict[str, object]]:
        events = self.tail(max(limit, 1))
        if level:
            events = [event for event in events if str(event.get("level", "")).lower() == level.lower()]
        if source:
            events = [event for event in events if str(event.get("source", "")).lower() == source.lower()]
        return events

    def delete(self, *, level: str = "", source: str = "") -> int:
        if not self.path.exists():
            return 0
        kept: list[str] = []
        deleted = 0
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                kept.append(line)
                continue
            if not isinstance(event, dict):
                kept.append(line)
                continue
            level_match = not level or str(event.get("level", "")).lower() == level.lower()
            source_match = not source or str(event.get("source", "")).lower() == source.lower()
            if level_match and source_match:
                deleted += 1
            else:
                kept.append(line)
        self.path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
        return deleted
