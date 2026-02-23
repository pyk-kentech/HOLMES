from __future__ import annotations

from abc import ABC, abstractmethod
import json
from pathlib import Path
import queue as queue_mod
import time
from typing import Iterator

from engine.io.events import Event, normalize_event


class EventSource(ABC):
    @abstractmethod
    def __iter__(self) -> Iterator[Event]:
        raise NotImplementedError


class FileJsonlSource(EventSource):
    def __init__(self, path: str | Path, follow: bool = False, poll_interval_sec: float = 0.2) -> None:
        self.path = Path(path)
        self.follow = bool(follow)
        self.poll_interval_sec = float(poll_interval_sec)

    def __iter__(self) -> Iterator[Event]:
        with self.path.open("r", encoding="utf-8") as f:
            index = 0
            while True:
                line = f.readline()
                if not line:
                    if self.follow:
                        time.sleep(self.poll_interval_sec)
                        continue
                    break
                line = line.strip()
                if not line:
                    continue
                index += 1
                raw = json.loads(line)
                if not isinstance(raw, dict):
                    continue
                yield normalize_event(raw, index)


class InMemoryQueueSource(EventSource):
    """
    In-memory streaming source for tests/local producers.

    The queue is expected to contain `Event` objects and optional `None` as a stop token.
    """

    def __init__(self, q: queue_mod.Queue[Event | None], timeout_sec: float = 0.5, stop_token: Event | None = None) -> None:
        self.q = q
        self.timeout_sec = float(timeout_sec)
        self.stop_token = stop_token

    def __iter__(self) -> Iterator[Event]:
        while True:
            try:
                item = self.q.get(timeout=self.timeout_sec)
            except queue_mod.Empty:
                break
            if item is self.stop_token:
                break
            if isinstance(item, Event):
                yield item


# TODO(KAFKA):
# class KafkaSource(EventSource):
#   - consume from Kafka topic, map message -> Event
#   - commit offsets
#   - handle rebalance
