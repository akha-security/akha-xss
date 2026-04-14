"""Tests for payload intelligence components."""

import unittest
import uuid

from akha.payloads.mutator import PayloadMutator
from akha.payloads.planner import PayloadPlanner
from akha.payloads.learning import LearningEngine
from akha.payloads.generator import PayloadGenerator
from akha.core.config import Config


class TestPayloadIntelligence(unittest.TestCase):
    def _engine(self):
        cfg = Config.default()
        cfg.learning_data_file = f"output/test_payload_intelligence_stats_{uuid.uuid4().hex}.json"
        return LearningEngine(cfg)

    def test_mutator_generates_variants(self):
        mutator = PayloadMutator()
        variants = mutator.mutate(["<img src=x onerror=alert(1)>"])
        self.assertGreater(len(variants), 0)

    def test_planner_dedupes_semantic_duplicates(self):
        planner = PayloadPlanner()
        payloads = [
            "<img src=x onerror=alert(1)>",
            "<img  src=x  onerror=alert(1)>",
            "<img src=x oNerRor=alert(1)>",
        ]
        deduped = planner.dedupe(payloads)
        self.assertEqual(len(deduped), 1)

    def test_learning_ucb_returns_payloads(self):
        engine = self._engine()
        engine.record_success("p1", "HTML", domain="example.com")
        engine.record_failure("p2", "HTML", domain="example.com")
        ranked = engine.get_best_payloads_ucb(context="HTML", domain="example.com", limit=2)
        self.assertGreaterEqual(len(ranked), 1)

    def test_learning_tracks_failure_taxonomy(self):
        engine = self._engine()
        engine.record_failure(
            "p1",
            "HTML",
            domain="example.com",
            failure_reason="encoded",
            endpoint_profile="api_read",
        )
        stats = engine.get_stats()
        self.assertIn("failure_reasons", stats)
        self.assertEqual(stats["failure_reasons"].get("encoded"), 1)

    def test_ucb_prefers_matching_endpoint_profile(self):
        engine = self._engine()
        for _ in range(3):
            engine.record_success(
                "profiled_payload",
                "HTML",
                domain="example.com",
                endpoint_profile="auth",
            )
            engine.record_failure(
                "generic_payload",
                "HTML",
                domain="example.com",
                endpoint_profile="auth",
            )

        ranked = engine.get_best_payloads_ucb(
            context="HTML",
            domain="example.com",
            endpoint_profile="auth",
            limit=2,
            exploration=0.0,
        )
        self.assertGreaterEqual(len(ranked), 1)
        self.assertEqual(ranked[0], "profiled_payload")

    def test_ucb_similarity_warm_start_for_related_domain(self):
        engine = self._engine()
        for _ in range(3):
            engine.record_success(
                "warm_payload",
                "HTML",
                domain="https://api.shop.example.com/v1/search",
                endpoint_profile="api_read",
                encoding_profile="mixed",
            )

        ranked = engine.get_best_payloads_ucb(
            context="HTML",
            domain="https://portal.shop.example.com/search",
            endpoint_profile="api_read",
            encoding_profile="mixed",
            limit=3,
            exploration=0.0,
        )
        self.assertIn("warm_payload", ranked)

    def test_generator_minimal_grammar_first(self):
        gen = PayloadGenerator()
        payloads = gen.generate(
            context="html",
            chars={c: "raw" for c in '<>"\'`()/'},
            marker="class=akha",
            minimal_grammar=True,
        )
        self.assertGreater(len(payloads), 0)
        self.assertTrue(any(p.startswith("<svg/onload=") for p in payloads[:5]))

    def test_generator_minimal_grammar_can_be_disabled(self):
        gen = PayloadGenerator()
        payloads = gen.generate(
            context="javascript",
            chars={c: "raw" for c in '<>"\'`()/'},
            quote_type='"',
            minimal_grammar=False,
        )
        self.assertGreater(len(payloads), 0)
        self.assertNotEqual(payloads[0], '";alert(1)//')

    def test_learning_respects_configurable_weights(self):
        cfg = Config.default()
        cfg.learning_data_file = f"output/test_payload_weight_stats_{uuid.uuid4().hex}.json"
        cfg.payload_context_weight = 0.4
        cfg.payload_encoding_weight = 0.3
        cfg.payload_waf_confidence_weight = 0.2
        cfg.ucb_exploration_factor = 1.1
        engine = LearningEngine(cfg)

        engine.record_success(
            "weighted_payload",
            "HTML",
            domain="example.com",
            endpoint_profile="auth",
            encoding_profile="mixed",
        )

        ranked = engine.get_best_payloads_ucb(
            context="HTML",
            domain="example.com",
            endpoint_profile="auth",
            encoding_profile="mixed",
            waf_confidence=0.8,
            limit=1,
        )
        self.assertEqual(ranked[0], "weighted_payload")


if __name__ == "__main__":
    unittest.main()
