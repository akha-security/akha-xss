"""
Adaptive Payload Intelligence — self-learning scoring system for XSS payloads.

Tracks per-payload, per-context, per-WAF, and **per-domain** effectiveness and
uses a Bayesian-inspired scoring formula to rank payloads:

    score = (success_count + 1) / (fail_count + 1)   ×  waf_penalty

    waf_penalty = 0.5  when WAF actively blocked the payload
                  1.0  otherwise

Higher scores surface payloads that have historically worked in a given context
/ domain.  WAF-blocked payloads are automatically demoted so they're tried last.

The module is:
  • Thread-safe (single ``threading.Lock``).
  • Deferred-write (dirty flag + ``flush()``).
  • Backward-compatible — migrates the old v1 format on first load.
  • Designed for zero-copy reads: ``get_ranked_payloads`` and
    ``get_best_payloads`` return fresh lists, never internal refs.
"""

import json
import os
import threading
import math
from importlib import resources
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


_WAF_PENALTY = 0.5



def _domain_key(url_or_domain: str) -> str:
    """Normalise a URL or bare domain to a consistent domain key."""
    if "://" in url_or_domain:
        parsed = urlparse(url_or_domain)
        return (parsed.hostname or parsed.netloc or url_or_domain).lower()
    return url_or_domain.strip().lower()


def _domain_family(url_or_domain: str) -> str:
    """Return a coarse domain family key for warm-start grouping."""
    host = _domain_key(url_or_domain)
    parts = [p for p in host.split('.') if p]
    if len(parts) >= 3 and len(parts[-1]) == 2 and len(parts[-2]) <= 3:
        return '.'.join(parts[-3:])
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return host


def _similarity_keys(url_or_domain: str) -> List[str]:
    """Build coarse warm-start keys from host family + route surface."""
    url_or_domain = (url_or_domain or '').strip()
    if not url_or_domain:
        return []

    if '://' in url_or_domain:
        parsed = urlparse(url_or_domain)
        path = (parsed.path or '').lower()
    else:
        path = ''

    keys: List[str] = []
    family = _domain_family(url_or_domain)
    if family:
        keys.append(f"family:{family}")

    segs = [s for s in path.split('/') if s]
    if segs:
        keys.append(f"path0:{segs[0]}")

    if '/api/' in path or (segs and segs[0] == 'api'):
        keys.append('surface:api')
    if any(token in path for token in ('/auth', '/login', '/signin', '/session', '/token')):
        keys.append('surface:auth')

    return list(dict.fromkeys(keys))


def _score(success: int, fail: int, waf_blocked: int = 0) -> float:
    """Bayesian scoring with WAF penalty.

    score = ((success + 1) / (fail + 1))  *  (0.5 ** waf_blocked_ratio)

    The +1 Laplace smoothing prevents ÷0 and cold-start domination.
    """
    base = (success + 1) / (fail + 1)
    total = success + fail
    if total > 0 and waf_blocked > 0:
        waf_ratio = waf_blocked / total
        base *= (1.0 - waf_ratio * (1.0 - _WAF_PENALTY))
    return round(base, 6)


def _ensure_entry(store: Dict, key: str) -> Dict:
    """Return (or create) a stats entry inside *store*."""
    if key not in store:
        store[key] = {
            "success_count": 0,
            "fail_count": 0,
            "waf_blocked": 0,
            "failure_reasons": {},
            "endpoint_profiles": {},
            "encoding_profiles": {},
        }
    else:
        # Keep compatibility with old persisted files that lack Phase 4 fields.
        store[key].setdefault("failure_reasons", {})
        store[key].setdefault("endpoint_profiles", {})
        store[key].setdefault("encoding_profiles", {})
    return store[key]



class LearningEngine:
    """Adaptive payload scoring engine with per-domain learning.

    Public API (unchanged from v1 — drop-in replacement):
        record_success(payload, context, waf_name, *, domain)
        record_failure(payload, context, waf_name, *, domain, waf_detected)
        get_best_payloads(context, waf_name, limit, *, domain)
        get_stats()
        flush()

    New API:
        get_ranked_payloads(domain, context)
        update_payload_result(domain, payload, success, waf_detected, *, context)
    """

    def __init__(self, config: Any) -> None:
        self.config = config
        self.data_file: str = getattr(config, "learning_data_file",
                                       "data/learning/payload_stats.json")
        self._lock = threading.Lock()
        self._dirty = False
        self.stats: Dict = self._load_stats()


    def _load_stats(self) -> Dict:
        """Load stats from disk, migrating v1 format if necessary."""
        data: Dict = {
            "version": 2,
            "global": {},     # payload → {success_count, fail_count, waf_blocked}
            "contexts": {},   # context → {payload → stats}
            "wafs": {},       # waf_name → {payload → stats}
            "domains": {},    # domain → {payload → stats}
            "similarity": {}, # warm-start key → {payload → stats}
        }

        raw = None
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, "r", encoding="utf-8") as f:
                    raw = json.load(f)
            except Exception:
                raw = None
        else:
            try:
                resource_path = resources.files('akha').joinpath('data/learning/payload_stats.json')
                with resource_path.open('r', encoding='utf-8') as f:
                    raw = json.load(f)
            except Exception:
                raw = None

        if raw is None:
            return data

        if raw.get("version") == 2:
            for key in ("global", "contexts", "wafs", "domains", "similarity"):
                if key in raw:
                    data[key] = raw[key]
            # Opportunistic migration for existing entries.
            for namespace in ("global",):
                for payload in list(data.get(namespace, {}).keys()):
                    _ensure_entry(data[namespace], payload)
            for namespace in ("contexts", "wafs", "domains", "similarity"):
                for _, scoped in data.get(namespace, {}).items():
                    if not isinstance(scoped, dict):
                        continue
                    for payload in list(scoped.keys()):
                        _ensure_entry(scoped, payload)
            return data

        v1_payloads = raw.get("payloads", {})
        for payload, pstats in v1_payloads.items():
            sc = pstats.get("success_count", 0)
            tt = pstats.get("total_tests", 0)
            fc = max(tt - sc, 0)
            data["global"][payload] = {
                "success_count": sc,
                "fail_count": fc,
                "waf_blocked": 0,
                "failure_reasons": {},
                "endpoint_profiles": {},
                "encoding_profiles": {},
            }

        v1_contexts = raw.get("contexts", {})
        for ctx, ctx_payloads in v1_contexts.items():
            data["contexts"][ctx] = {}
            for payload, cstats in ctx_payloads.items():
                sc = cstats.get("success_count", 0)
                tt = cstats.get("total_tests", 0)
                data["contexts"][ctx][payload] = {
                    "success_count": sc,
                    "fail_count": max(tt - sc, 0),
                    "waf_blocked": 0,
                    "failure_reasons": {},
                    "endpoint_profiles": {},
                    "encoding_profiles": {},
                }

        v1_wafs = raw.get("wafs", {})
        for waf, waf_payloads in v1_wafs.items():
            data["wafs"][waf] = {}
            for payload, wstats in waf_payloads.items():
                sc = wstats.get("success_count", 0)
                tt = wstats.get("total_tests", 0)
                data["wafs"][waf][payload] = {
                    "success_count": sc,
                    "fail_count": max(tt - sc, 0),
                    "waf_blocked": 0,
                    "failure_reasons": {},
                    "endpoint_profiles": {},
                    "encoding_profiles": {},
                }

        return data

    def _save_stats(self) -> None:
        """Write stats to disk if dirty."""
        if not self._dirty:
            return
        try:
            os.makedirs(os.path.dirname(self.data_file) or ".", exist_ok=True)
            with open(self.data_file, "w", encoding="utf-8") as f:
                json.dump(self.stats, f, indent=2, ensure_ascii=False)
            self._dirty = False
        except Exception as e:
            if getattr(self.config, "verbose", False):
                print(f"[LearningEngine] save error: {e}")

    def flush(self) -> None:
        """Force-write pending stats to disk."""
        with self._lock:
            self._dirty = True
            self._save_stats()


    def _inc(self, store: Dict, key: str, *, success: bool,
             waf_detected: bool = False,
             failure_reason: Optional[str] = None,
             endpoint_profile: Optional[str] = None,
             encoding_profile: Optional[str] = None) -> None:
        """Increment counters for *key* inside *store*."""
        entry = _ensure_entry(store, key)
        if success:
            entry["success_count"] += 1
        else:
            entry["fail_count"] += 1
            if failure_reason:
                reasons = entry.setdefault("failure_reasons", {})
                reasons[failure_reason] = reasons.get(failure_reason, 0) + 1
        if waf_detected and not success:
            entry["waf_blocked"] += 1
        if endpoint_profile:
            profile_stats = entry.setdefault("endpoint_profiles", {}).setdefault(
                endpoint_profile, {"success_count": 0, "fail_count": 0}
            )
            if success:
                profile_stats["success_count"] = profile_stats.get("success_count", 0) + 1
            else:
                profile_stats["fail_count"] = profile_stats.get("fail_count", 0) + 1
        if encoding_profile:
            profile_stats = entry.setdefault("encoding_profiles", {}).setdefault(
                encoding_profile, {"success_count": 0, "fail_count": 0}
            )
            if success:
                profile_stats["success_count"] = profile_stats.get("success_count", 0) + 1
            else:
                profile_stats["fail_count"] = profile_stats.get("fail_count", 0) + 1


    def record_success(self, payload: str, context: str,
                       waf_name: Optional[str] = None, *,
                       domain: Optional[str] = None,
                       endpoint_profile: Optional[str] = None,
                       encoding_profile: Optional[str] = None) -> None:
        """Record a successful payload execution.

        Backward-compatible with the v1 call signature used by
        ``xss_engine.py``:  ``record_success(payload, context, waf_name)``.
        """
        with self._lock:
            self._inc(
                self.stats["global"], payload, success=True,
                endpoint_profile=endpoint_profile,
                encoding_profile=encoding_profile,
            )

            ctx_store = self.stats["contexts"].setdefault(context, {})
            self._inc(
                ctx_store, payload, success=True,
                endpoint_profile=endpoint_profile,
                encoding_profile=encoding_profile,
            )

            if waf_name:
                waf_store = self.stats["wafs"].setdefault(waf_name, {})
                self._inc(
                    waf_store, payload, success=True,
                    endpoint_profile=endpoint_profile,
                    encoding_profile=encoding_profile,
                )

            if domain:
                dk = _domain_key(domain)
                dom_store = self.stats["domains"].setdefault(dk, {})
                self._inc(
                    dom_store, payload, success=True,
                    endpoint_profile=endpoint_profile,
                    encoding_profile=encoding_profile,
                )

                if getattr(self.config, "payload_similarity_warm_start", True):
                    for sim_key in _similarity_keys(domain):
                        sim_store = self.stats["similarity"].setdefault(sim_key, {})
                        self._inc(
                            sim_store, payload, success=True,
                            endpoint_profile=endpoint_profile,
                            encoding_profile=encoding_profile,
                        )

            self._dirty = True


    def record_failure(self, payload: str, context: str,
                       waf_name: Optional[str] = None, *,
                       domain: Optional[str] = None,
                       waf_detected: bool = False,
                       failure_reason: Optional[str] = None,
                       endpoint_profile: Optional[str] = None,
                       encoding_profile: Optional[str] = None) -> None:
        """Record a failed payload attempt.

        Parameters
        ----------
        waf_detected : bool
            True when a WAF actively blocked this payload (403 / challenge
            page).  The payload score is penalised accordingly.
        """
        with self._lock:
            self._inc(self.stats["global"], payload, success=False,
                      waf_detected=waf_detected,
                      failure_reason=failure_reason,
                      endpoint_profile=endpoint_profile,
                      encoding_profile=encoding_profile)

            ctx_store = self.stats["contexts"].setdefault(context, {})
            self._inc(ctx_store, payload, success=False,
                      waf_detected=waf_detected,
                      failure_reason=failure_reason,
                      endpoint_profile=endpoint_profile,
                      encoding_profile=encoding_profile)

            if waf_name:
                waf_store = self.stats["wafs"].setdefault(waf_name, {})
                self._inc(waf_store, payload, success=False,
                          waf_detected=waf_detected,
                          failure_reason=failure_reason,
                          endpoint_profile=endpoint_profile,
                          encoding_profile=encoding_profile)

            if domain:
                dk = _domain_key(domain)
                dom_store = self.stats["domains"].setdefault(dk, {})
                self._inc(dom_store, payload, success=False,
                          waf_detected=waf_detected,
                          failure_reason=failure_reason,
                          endpoint_profile=endpoint_profile,
                          encoding_profile=encoding_profile)

                if getattr(self.config, "payload_similarity_warm_start", True):
                    for sim_key in _similarity_keys(domain):
                        sim_store = self.stats["similarity"].setdefault(sim_key, {})
                        self._inc(
                            sim_store, payload, success=False,
                            waf_detected=waf_detected,
                            failure_reason=failure_reason,
                            endpoint_profile=endpoint_profile,
                            encoding_profile=encoding_profile,
                        )

            self._dirty = True


    def update_payload_result(self, domain: str, payload: str,
                              success: bool,
                              waf_detected: bool = False, *,
                              context: Optional[str] = None) -> None:
        """Single-call update for both success and failure.

        Delegates to ``record_success`` / ``record_failure`` so all stores
        (global, context, WAF, domain) are updated.
        """
        if success:
            self.record_success(payload, context or "html", domain=domain)
        else:
            self.record_failure(payload, context or "html", domain=domain,
                                waf_detected=waf_detected)


    def get_ranked_payloads(self, domain: str,
                            context: Optional[str] = None,
                            limit: int = 20) -> List[Dict]:
        """Return payloads ranked by adaptive score for *domain* + *context*.

        Falls back to global stats when domain-specific data is sparse.

        Returns
        -------
        list[dict]
            Each entry: ``{"payload", "score", "success_count",
            "fail_count", "waf_blocked"}``.
        """
        with self._lock:
            return self._ranked_locked(domain, context, limit)

    def _ranked_locked(self, domain: str, context: Optional[str],
                       limit: int) -> List[Dict]:
        dk = _domain_key(domain)
        dom_data = self.stats["domains"].get(dk, {})
        sim_keys = _similarity_keys(domain)

        merged: Dict[str, Dict] = {}

        def _merge_from(source: Dict[str, Dict], weight: float = 1.0) -> None:
            for payload, entry in source.items():
                if payload not in merged:
                    merged[payload] = {
                        "success_count": 0.0,
                        "fail_count": 0.0,
                        "waf_blocked": 0.0,
                    }
                merged[payload]["success_count"] += float(entry.get("success_count", 0)) * weight
                merged[payload]["fail_count"] += float(entry.get("fail_count", 0)) * weight
                merged[payload]["waf_blocked"] += float(entry.get("waf_blocked", 0)) * weight

        source = self.stats["global"]
        if context and context in self.stats["contexts"]:
            source = self.stats["contexts"][context]
        _merge_from(source, 1.0)
        _merge_from(dom_data, 1.0)

        if getattr(self.config, "payload_similarity_warm_start", True):
            for sim_key in sim_keys:
                sim_source = self.stats.get("similarity", {}).get(sim_key, {})
                _merge_from(sim_source, 0.35)

        ranked = []
        for payload, e in merged.items():
            sc = e.get("success_count", 0)
            fc = e.get("fail_count", 0)
            wb = e.get("waf_blocked", 0)
            ranked.append({
                "payload": payload,
                "score": _score(sc, fc, wb),
                "success_count": sc,
                "fail_count": fc,
                "waf_blocked": wb,
            })

        ranked.sort(key=lambda r: (r["score"], r["success_count"]), reverse=True)
        return ranked[:limit]


    def get_best_payloads(self, context: Optional[str] = None,
                          waf_name: Optional[str] = None,
                          limit: int = 20, *,
                          domain: Optional[str] = None) -> List[str]:
        """Return the top *limit* payload strings, ranked by score.

        Backward-compatible with v1 callers that pass only
        ``(context, waf_name, limit)``.
        """
        with self._lock:
            if domain:
                entries = self._ranked_locked(domain, context, limit)
                return [e["payload"] for e in entries]

            if waf_name and waf_name in self.stats["wafs"]:
                source = self.stats["wafs"][waf_name]
            elif context and context in self.stats["contexts"]:
                source = self.stats["contexts"][context]
            else:
                source = self.stats["global"]

            scored = []
            for payload, e in source.items():
                sc = e.get("success_count", 0)
                fc = e.get("fail_count", 0)
                wb = e.get("waf_blocked", 0)
                scored.append((payload, _score(sc, fc, wb), sc))

            scored.sort(key=lambda x: (x[1], x[2]), reverse=True)
            return [p for p, _, _ in scored[:limit]]

    def get_best_payloads_ucb(self, context: Optional[str] = None,
                              waf_name: Optional[str] = None,
                              limit: int = 20, *,
                              domain: Optional[str] = None,
                              endpoint_profile: Optional[str] = None,
                              encoding_profile: Optional[str] = None,
                              waf_confidence: Optional[float] = None,
                              exploration: float = 1.4) -> List[str]:
        """Return payloads ranked by UCB1 to balance exploration/exploitation."""
        with self._lock:
            try:
                exploration = float(
                    exploration
                    if exploration is not None
                    else getattr(self.config, "ucb_exploration_factor", 1.4)
                )
            except (TypeError, ValueError):
                exploration = 1.4

            context_weight = max(0.0, float(getattr(self.config, "payload_context_weight", 0.25) or 0.25))
            encoding_weight = max(0.0, float(getattr(self.config, "payload_encoding_weight", 0.15) or 0.15))
            waf_weight = max(0.0, min(float(getattr(self.config, "payload_waf_confidence_weight", 0.10) or 0.10), 1.0))

            if domain:
                entries = self._ranked_locked(domain, context, max(limit * 3, limit))
                source = {
                    e["payload"]: {
                        "success_count": e.get("success_count", 0),
                        "fail_count": e.get("fail_count", 0),
                    }
                    for e in entries
                }
            elif waf_name and waf_name in self.stats["wafs"]:
                source = self.stats["wafs"][waf_name]
            elif context and context in self.stats["contexts"]:
                source = self.stats["contexts"][context]
            else:
                source = self.stats["global"]

            total_trials = 0
            for e in source.values():
                total_trials += e.get("success_count", 0) + e.get("fail_count", 0)
            total_trials = max(total_trials, 1)

            ranked = []
            for payload, e in source.items():
                success = e.get("success_count", 0)
                fail = e.get("fail_count", 0)
                n = success + fail
                mean = (success + 1) / (n + 2)  # beta prior
                bonus = exploration * math.sqrt(math.log(total_trials + 1) / (n + 1))

                profile_boost = 0.0
                if endpoint_profile:
                    pstats = e.get("endpoint_profiles", {}).get(endpoint_profile, {})
                    ps = pstats.get("success_count", 0)
                    pf = pstats.get("fail_count", 0)
                    pt = ps + pf
                    if pt > 0:
                        profile_rate = (ps + 1) / (pt + 2)
                        profile_boost = context_weight * profile_rate

                encoding_boost = 0.0
                if encoding_profile:
                    estats = e.get("encoding_profiles", {}).get(encoding_profile, {})
                    es = estats.get("success_count", 0)
                    ef = estats.get("fail_count", 0)
                    et = es + ef
                    if et > 0:
                        encoding_rate = (es + 1) / (et + 2)
                        encoding_boost = encoding_weight * encoding_rate

                context_mult = 1.0
                multipliers = getattr(self.config, "payload_context_multipliers", None)
                if isinstance(multipliers, dict) and context:
                    try:
                        context_mult = max(0.5, min(float(multipliers.get(str(context).lower(), 1.0)), 2.5))
                    except (TypeError, ValueError):
                        context_mult = 1.0

                waf_mod = 1.0
                if waf_confidence is not None:
                    try:
                        waf_conf = max(0.0, min(1.0, float(waf_confidence)))
                        waf_mod = (1.0 - waf_weight) + (waf_weight * waf_conf)
                    except (TypeError, ValueError):
                        waf_mod = 1.0

                ranked.append((payload, (mean + bonus + profile_boost + encoding_boost) * waf_mod * context_mult, success))

            ranked.sort(key=lambda x: (x[1], x[2]), reverse=True)
            return [p for p, _, _ in ranked[:limit]]


    def get_stats(self) -> Dict:
        """Aggregate statistics for CLI / reporting."""
        with self._lock:
            g = self.stats["global"]
            total_payloads = len(g)
            total_success = sum(e.get("success_count", 0) for e in g.values())
            total_fail = sum(e.get("fail_count", 0) for e in g.values())
            total_tests = total_success + total_fail
            total_waf = sum(e.get("waf_blocked", 0) for e in g.values())
            failure_reasons = {}
            for e in g.values():
                for reason, count in e.get("failure_reasons", {}).items():
                    failure_reasons[reason] = failure_reasons.get(reason, 0) + int(count)

            top_payloads = []
            for payload, e in g.items():
                sc = e.get("success_count", 0)
                fc = e.get("fail_count", 0)
                wb = e.get("waf_blocked", 0)
                tt = sc + fc
                if tt >= 3:
                    top_payloads.append({
                        "payload": payload,
                        "score": _score(sc, fc, wb),
                        "success_rate": sc / tt if tt else 0,
                        "total_tests": tt,
                    })

            top_payloads.sort(key=lambda x: x["score"], reverse=True)

            return {
                "total_payloads": total_payloads,
                "total_tests": total_tests,
                "total_successes": total_success,
                "total_failures": total_fail,
                "total_waf_blocks": total_waf,
                "failure_reasons": failure_reasons,
                "avg_success_rate": total_success / total_tests if total_tests else 0,
                "domains_tracked": len(self.stats["domains"]),
                "top_payloads": top_payloads[:10],
            }
