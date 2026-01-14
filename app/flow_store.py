from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cachetools import TTLCache


@dataclass
class FlowState:
    cookies: Dict[str, str]
    params: list[tuple[str, str]]
    code_verifier: str
    transaction_id: str
    locale: str


class FlowStore:
    def __init__(self, maxsize: int = 1024, ttl_seconds: int = 600):
        self._cache: TTLCache[str, FlowState] = TTLCache(maxsize=maxsize, ttl=ttl_seconds)

    def create(self, state: FlowState) -> str:
        flow_id = str(uuid.uuid4())
        self._cache[flow_id] = state
        return flow_id

    def get(self, flow_id: str) -> Optional[FlowState]:
        return self._cache.get(flow_id)

    def delete(self, flow_id: str) -> None:
        self._cache.pop(flow_id, None)
