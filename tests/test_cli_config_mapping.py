"""Regression tests for CLI -> Config mapping and proxy TLS behavior."""

import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
_HANDLERS_PATH = ROOT / "akha" / "cli" / "handlers.py"
_SPEC = importlib.util.spec_from_file_location("akha_cli_handlers_under_test", _HANDLERS_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC is not None and _SPEC.loader is not None
_SPEC.loader.exec_module(_MODULE)
_build_config = _MODULE._build_config


class TestCliConfigMapping(unittest.TestCase):
    def _args(self, **overrides):
        base = {
            "config": None,
            "proxy": None,
            "proxy_list": None,
            "mode": "full",
            "payload_strategy": "auto",
            "max_pages": 1500,
            "max_depth": 3,
            "output": "output",
            "format": "html",
            "threads": 10,
            "timeout": 10,
            "verbose": False,
            "quiet": True,
            "rate_limit": 10,
            "max_scan_seconds": 0,
            "max_requests": 0,
            "max_payloads": 0,
            "max_payloads_per_param": 0,
            "max_payloads_per_endpoint": 0,
            "budget_auto_fallback": True,
            "budget_fallback_trigger": 0.85,
            "distributed_task_queue": True,
            "dynamic_task_lease": True,
            "task_lease_seconds": 120,
            "task_max_retries": 3,
            "task_worker_id": None,
            "resume_checkpoint_seconds": 20,
            "strict_scope_guard": True,
            "scope_guard_max_pages": 5000,
            "allow_ssl_fallback": False,
            "custom_payloads": None,
            "encode": "auto",
            "include": [],
            "exclude": [],
            "dom_xss_enabled": True,
            "stored_xss_enabled": True,
            "deep_scan": False,
            "dynamic_crawling": True,
            "stateful_spa_discovery": True,
            "spa_state_budget": 8,
            "discovery_profile": "auto",
            "aggressive": False,
            "profile": "balanced",
            "api_mode": False,
            "test_post": False,
            "per_host_rate_limit": True,
            "per_path_rate_limit": True,
            "path_rate_multiplier": 0.75,
            "proxy_cooldown_seconds": 60,
            "endpoint_backoff_profiles": True,
            "endpoint_backoff_overrides": None,
            "risk_prioritization": True,
            "risk_priority_top_k": 300,
            "auto_reauth": True,
            "probe_sensitive": False,
            "test_mxss": True,
            "test_angular": True,
            "test_graphql": True,
            "test_websockets": False,
            "test_headers": False,
            "test_cookies": False,
            "test_path_params": False,
            "verified_only": False,
            "execution_verify_firefox": False,
            "payload_failure_taxonomy": True,
            "payload_context_bandit": True,
            "payload_minimal_grammar": True,
            "payload_similarity_warm_start": True,
            "ucb_exploration": 1.4,
            "payload_context_weight": 0.25,
            "payload_encoding_weight": 0.15,
            "payload_waf_weight": 0.10,
            "min_confidence": 60,
            "collaborator_url": None,
            "oast_enabled": False,
            "webhook_url": None,
            "webhook_platform": "auto",
            "telegram_chat_id": None,
            "resume": None,
            "no_verify_ssl": False,
            "cookie": None,
            "header": [],
            "auth_url": None,
            "auth_data": None,
            "bearer_token": None,
            "auth_plugin": None,
            "auth_plugin_options": None,
        }
        base.update(overrides)
        return SimpleNamespace(**base)

    def test_build_config_maps_recent_cli_flags(self):
        args = self._args(
            dynamic_crawling=False,
            oast_enabled=True,
            proxy_list="proxies.txt",
            auto_reauth=False,
        )

        cfg = _build_config(args)
        self.assertIsNotNone(cfg)
        self.assertFalse(cfg.dynamic_crawling)
        self.assertTrue(cfg.oast_enabled)
        self.assertEqual(cfg.proxy_list, "proxies.txt")
        self.assertFalse(cfg.auto_reauth)

    def test_proxy_mode_forces_insecure_compat_flags(self):
        args = self._args(proxy="http://127.0.0.1:8080", quiet=True)

        cfg = _build_config(args)
        self.assertIsNotNone(cfg)
        self.assertFalse(cfg.verify_ssl)
        self.assertTrue(cfg.allow_ssl_fallback)

    def test_build_config_maps_phase3_new_flags(self):
        args = self._args(
            stateful_spa_discovery=False,
            spa_state_budget=3,
            discovery_profile="authenticated",
            per_host_rate_limit=False,
            per_path_rate_limit=False,
            path_rate_multiplier=0.5,
            proxy_cooldown_seconds=90,
            endpoint_backoff_profiles=False,
            risk_prioritization=False,
            risk_priority_top_k=0,
            execution_verify_firefox=True,
            endpoint_backoff_overrides='{"auth": {"penalty_mult": 2.2}}',
        )

        cfg = _build_config(args)
        self.assertIsNotNone(cfg)
        self.assertFalse(cfg.stateful_spa_discovery)
        self.assertEqual(cfg.spa_state_transition_budget, 3)
        self.assertEqual(cfg.discovery_profile, "authenticated")
        self.assertFalse(cfg.per_host_rate_limit)
        self.assertFalse(cfg.per_path_rate_limit)
        self.assertEqual(cfg.path_rate_multiplier, 0.5)
        self.assertEqual(cfg.proxy_cooldown_seconds, 90)
        self.assertFalse(cfg.endpoint_backoff_profiles)
        self.assertFalse(cfg.risk_prioritization)
        self.assertEqual(cfg.risk_priority_top_k, 0)
        self.assertTrue(cfg.execution_verify_firefox)
        self.assertEqual(cfg.endpoint_backoff_profile_overrides["auth"]["penalty_mult"], 2.2)

    def test_build_config_maps_phase4_payload_learning_flags(self):
        args = self._args(
            payload_failure_taxonomy=False,
            payload_context_bandit=False,
            payload_minimal_grammar=False,
            payload_similarity_warm_start=False,
        )
        cfg = _build_config(args)
        self.assertIsNotNone(cfg)
        self.assertFalse(cfg.payload_failure_taxonomy)
        self.assertFalse(cfg.payload_context_bandit)
        self.assertFalse(cfg.payload_minimal_grammar)
        self.assertFalse(cfg.payload_similarity_warm_start)

    def test_build_config_maps_phase5_budgets_and_guardrails(self):
        args = self._args(
            max_scan_seconds=120,
            max_requests=500,
            max_payloads=300,
            max_payloads_per_param=12,
            max_payloads_per_endpoint=60,
            budget_auto_fallback=False,
            budget_fallback_trigger=0.9,
            distributed_task_queue=False,
            dynamic_task_lease=False,
            task_lease_seconds=180,
            task_max_retries=5,
            task_worker_id="worker-1",
            resume_checkpoint_seconds=15,
            strict_scope_guard=False,
            scope_guard_max_pages=2500,
            ucb_exploration=1.8,
            payload_context_weight=0.3,
            payload_encoding_weight=0.2,
            payload_waf_weight=0.2,
        )
        cfg = _build_config(args)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.scan_budget_seconds, 120)
        self.assertEqual(cfg.scan_budget_requests, 500)
        self.assertEqual(cfg.scan_budget_payloads, 300)
        self.assertEqual(cfg.max_payloads_per_param, 12)
        self.assertEqual(cfg.max_payloads_per_endpoint, 60)
        self.assertFalse(cfg.budget_auto_fallback)
        self.assertEqual(cfg.budget_fallback_trigger, 0.9)
        self.assertFalse(cfg.distributed_task_queue)
        self.assertFalse(cfg.dynamic_task_lease)
        self.assertEqual(cfg.task_lease_seconds, 180)
        self.assertEqual(cfg.task_max_retries, 5)
        self.assertEqual(cfg.task_worker_id, "worker-1")
        self.assertEqual(cfg.ucb_exploration_factor, 1.8)
        self.assertEqual(cfg.payload_context_weight, 0.3)
        self.assertEqual(cfg.payload_encoding_weight, 0.2)
        self.assertEqual(cfg.payload_waf_confidence_weight, 0.2)
        self.assertEqual(cfg.resume_checkpoint_interval_seconds, 15)
        self.assertFalse(cfg.strict_scope_guard)
        self.assertEqual(cfg.scope_guard_max_pages, 2500)

    def test_build_config_maps_auth_plugin_flags(self):
        args = self._args(
            auth_plugin="csrf-preflight",
            auth_plugin_options='{"preflight_url":"https://example.com/login"}',
        )
        cfg = _build_config(args)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.auth_plugin, "csrf-preflight")
        self.assertEqual(cfg.auth_plugin_options["preflight_url"], "https://example.com/login")

    def test_build_config_rejects_invalid_auth_plugin_options(self):
        args = self._args(auth_plugin_options='[1,2,3]')
        cfg = _build_config(args)
        self.assertIsNone(cfg)


if __name__ == "__main__":
    unittest.main()
