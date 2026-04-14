"""Distributed-ready task queue with lease/ack semantics and snapshot support."""

from __future__ import annotations

import threading
import time
import uuid
from typing import Dict, List, Optional


class DistributedTaskQueue:
    """In-memory queue model designed to be checkpointed/resumed safely."""

    def __init__(self):
        self._lock = threading.Lock()
        self._items: Dict[str, Dict] = {}
        self._order: List[str] = []
        self._task_key_to_id: Dict[str, str] = {}

    def enqueue_many(self, tasks: List[Dict]) -> List[str]:
        ids: List[str] = []
        with self._lock:
            for t in tasks:
                task_key = str((t.get("meta") or {}).get("task_key") or "")
                if task_key and task_key in self._task_key_to_id:
                    ids.append(self._task_key_to_id[task_key])
                    continue
                task_id = uuid.uuid4().hex
                item = {
                    "id": task_id,
                    "task_type": t.get("task_type", "generic"),
                    "payload": t.get("payload", {}),
                    "meta": t.get("meta", {}),
                    "status": "pending",
                    "lease_owner": None,
                    "lease_until": 0.0,
                    "attempts": 0,
                    "created_at": time.time(),
                    "updated_at": time.time(),
                }
                self._items[task_id] = item
                self._order.append(task_id)
                if task_key:
                    self._task_key_to_id[task_key] = task_id
                ids.append(task_id)
        return ids

    def claim(
        self,
        *,
        worker_id: str,
        max_items: int = 1,
        lease_seconds: int = 120,
        task_type: Optional[str] = None,
        max_attempts: int = 0,
    ) -> List[Dict]:
        claimed: List[Dict] = []
        now = time.time()
        lease_until = now + max(1, int(lease_seconds))

        with self._lock:
            for task_id in self._order:
                if len(claimed) >= max(1, int(max_items)):
                    break
                item = self._items.get(task_id)
                if not item:
                    continue
                if item.get("status") != "pending":
                    continue
                if task_type and item.get("task_type") != task_type:
                    continue
                attempts = int(item.get("attempts", 0))
                if max_attempts > 0 and attempts >= max_attempts:
                    item["status"] = "failed"
                    item["updated_at"] = now
                    continue
                item["status"] = "inflight"
                item["lease_owner"] = worker_id
                item["lease_until"] = lease_until
                item["attempts"] = attempts + 1
                item["updated_at"] = now
                claimed.append(dict(item))

        return claimed

    def ack(self, task_ids: List[str]) -> int:
        updated = 0
        now = time.time()
        with self._lock:
            for tid in task_ids:
                item = self._items.get(tid)
                if not item:
                    continue
                if item.get("status") != "inflight":
                    continue
                item["status"] = "completed"
                item["lease_owner"] = None
                item["lease_until"] = 0.0
                item["updated_at"] = now
                updated += 1
        return updated

    def nack(self, task_ids: List[str], *, requeue: bool = True) -> int:
        updated = 0
        now = time.time()
        with self._lock:
            for tid in task_ids:
                item = self._items.get(tid)
                if not item:
                    continue
                if item.get("status") != "inflight":
                    continue
                item["status"] = "pending" if requeue else "failed"
                item["lease_owner"] = None
                item["lease_until"] = 0.0
                item["updated_at"] = now
                updated += 1
        return updated

    def release_expired(self) -> int:
        released = 0
        now = time.time()
        with self._lock:
            for task_id in self._order:
                item = self._items.get(task_id)
                if not item:
                    continue
                if item.get("status") != "inflight":
                    continue
                if float(item.get("lease_until", 0.0)) > now:
                    continue
                item["status"] = "pending"
                item["lease_owner"] = None
                item["lease_until"] = 0.0
                item["updated_at"] = now
                released += 1
        return released

    @property
    def pending_count(self) -> int:
        with self._lock:
            return sum(1 for i in self._items.values() if i.get("status") == "pending")

    @property
    def inflight_count(self) -> int:
        with self._lock:
            return sum(1 for i in self._items.values() if i.get("status") == "inflight")

    @property
    def completed_count(self) -> int:
        with self._lock:
            return sum(1 for i in self._items.values() if i.get("status") == "completed")

    @property
    def failed_count(self) -> int:
        with self._lock:
            return sum(1 for i in self._items.values() if i.get("status") == "failed")

    def dead_letters(self) -> List[Dict]:
        with self._lock:
            return [dict(i) for i in self._items.values() if i.get("status") == "failed"]

    def snapshot(self, *, queue_name: str = "default") -> Dict:
        with self._lock:
            return {
                "queue_name": queue_name,
                "items": [dict(self._items[tid]) for tid in self._order if tid in self._items],
            }

    @classmethod
    def from_snapshot(cls, data: Dict) -> "DistributedTaskQueue":
        q = cls()
        items = data.get("items", []) if isinstance(data, dict) else []
        with q._lock:
            for item in items:
                tid = item.get("id")
                if not tid:
                    continue
                q._items[tid] = dict(item)
                q._order.append(tid)
                task_key = str((item.get("meta") or {}).get("task_key") or "")
                if task_key:
                    q._task_key_to_id[task_key] = tid
        return q
