"""Unit tests for distributed-ready lease/ack task queue."""

import unittest

from akha.core.task_queue import DistributedTaskQueue


class TestDistributedTaskQueue(unittest.TestCase):
    def test_claim_ack_and_counts(self):
        q = DistributedTaskQueue()
        q.enqueue_many([
            {"task_type": "reflected_xss", "payload": {"url": "a"}},
            {"task_type": "reflected_xss", "payload": {"url": "b"}},
        ])

        claimed = q.claim(worker_id="w1", max_items=2, lease_seconds=60, task_type="reflected_xss")
        self.assertEqual(len(claimed), 2)
        self.assertEqual(q.inflight_count, 2)

        q.ack([claimed[0]["id"]])
        self.assertEqual(q.completed_count, 1)

        q.nack([claimed[1]["id"]], requeue=True)
        self.assertEqual(q.pending_count, 1)

    def test_release_expired_requeues(self):
        q = DistributedTaskQueue()
        q.enqueue_many([
            {"task_type": "reflected_xss", "payload": {"url": "x"}},
        ])
        claimed = q.claim(worker_id="w1", max_items=1, lease_seconds=1)
        self.assertEqual(len(claimed), 1)

        snap = q.snapshot(queue_name="reflected_xss")
        item = snap["items"][0]
        item["lease_until"] = 0.0
        restored = DistributedTaskQueue.from_snapshot({"queue_name": "reflected_xss", "items": [item]})
        released = restored.release_expired()
        self.assertEqual(released, 1)
        self.assertEqual(restored.pending_count, 1)

    def test_snapshot_restore_roundtrip(self):
        q = DistributedTaskQueue()
        q.enqueue_many([
            {"task_type": "reflected_xss", "payload": {"url": "u1"}, "meta": {"k": 1}},
        ])
        snap = q.snapshot(queue_name="reflected_xss")

        cloned = DistributedTaskQueue.from_snapshot(snap)
        claimed = cloned.claim(worker_id="w2", max_items=1, lease_seconds=120, task_type="reflected_xss")
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0]["payload"]["url"], "u1")

    def test_max_attempts_moves_task_to_failed(self):
        q = DistributedTaskQueue()
        q.enqueue_many([
            {"task_type": "reflected_xss", "payload": {"url": "u2"}},
        ])

        first = q.claim(worker_id="w", max_items=1, lease_seconds=120, max_attempts=1)
        self.assertEqual(len(first), 1)
        q.nack([first[0]["id"]], requeue=True)

        second = q.claim(worker_id="w", max_items=1, lease_seconds=120, max_attempts=1)
        self.assertEqual(len(second), 0)
        self.assertEqual(q.failed_count, 1)

    def test_task_key_is_idempotent(self):
        q = DistributedTaskQueue()
        ids1 = q.enqueue_many([
            {"task_type": "reflected_xss", "payload": {"url": "x"}, "meta": {"task_key": "k1"}},
        ])
        ids2 = q.enqueue_many([
            {"task_type": "reflected_xss", "payload": {"url": "x"}, "meta": {"task_key": "k1"}},
        ])
        self.assertEqual(len(ids1), 1)
        self.assertEqual(ids1, ids2)


if __name__ == "__main__":
    unittest.main()
