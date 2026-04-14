"""
Configuration management
"""

from dataclasses import dataclass, field
from typing import Any, List, Dict, Optional
import yaml
import os


@dataclass
class Config:
    """Scanner configuration"""
    
    target_url: str = ""
    scan_mode: str = "full"  # full or url
    
    payload_strategy: str = "auto"  # auto, builtin, custom, hybrid
    scan_profile: str = "balanced"  # quick, balanced, deep
    
    max_depth: int = 3
    max_pages: int = 1500
    follow_redirects: bool = True
    parse_js: bool = True
    
    timeout: int = 10
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    verify_ssl: bool = True
    allow_ssl_fallback: bool = False
    proxy: Optional[str] = None
    proxy_list: Optional[str] = None     # Path to proxy list file for IP rotation
    proxy_cooldown_seconds: int = 60     # Quarantine duration for unhealthy proxies
    rate_limit: int = 10  # 10 req/s default - safe for real sites
    per_host_rate_limit: bool = True  # Enable host-aware throttling
    per_path_rate_limit: bool = True  # Enable path-aware throttling
    path_rate_multiplier: float = 0.75  # Path-specific rate relative to global rate
    endpoint_backoff_profiles: bool = True  # Use endpoint-class-aware backoff weights
    endpoint_backoff_profile_overrides: Optional[Dict[str, Dict[str, Any]]] = None  # Per-profile override map
    auto_reauth: bool = True             # Auto re-login when session expires (401/403)
    
    cookies: Optional[str] = None          # Cookie string: "name1=val1; name2=val2"
    custom_headers: Optional[Dict] = None  # Custom headers dict
    auth_url: Optional[str] = None         # Login URL for form-based auth
    auth_data: Optional[Dict] = None       # Login form data {"username": "x", "password": "y"}
    bearer_token: Optional[str] = None     # Bearer token for API auth
    auth_plugin: Optional[str] = None       # Optional auth flow helper (e.g. csrf-preflight, bearer-refresh)
    auth_plugin_options: Optional[Dict[str, Any]] = None  # Plugin-specific options map
    
    param_wordlist: Optional[str] = None
    context_aware: bool = True
    deep_scan: bool = False
    dynamic_crawling: bool = True    # Enable Playwright-based dynamic crawling
    stateful_spa_discovery: bool = True  # Try limited state transitions in dynamic crawling
    spa_state_transition_budget: int = 8  # Max interactive SPA transitions per page
    discovery_profile: str = "auto"  # auto | anonymous | authenticated | admin
    
    enable_waf_bypass: bool = True
    aggressive_mode: bool = False
    validate_findings: bool = True
    min_confidence_threshold: int = 60
    verified_only: bool = False
    
    test_mxss: bool = True           # Mutation XSS scanning
    test_external_js: bool = True    # Analyze external JS files for DOM XSS
    test_angular: bool = True        # AngularJS CSTI scanning
    test_graphql: bool = True        # GraphQL endpoint XSS scanning
    test_websockets: bool = False    # WebSocket XSS (off by default — slower)
    test_prototype_pollution: bool = True  # Prototype pollution → XSS
    
    test_headers: bool = False       # Test injectable HTTP headers (opt-in; can be noisy)
    test_cookies: bool = False       # Test cookie parameters (opt-in; can be noisy)
    test_path_params: bool = False   # Test URL path segments (opt-in; can be noisy)
    probe_sensitive: bool = False    # Probe sensitive files like /.env only when enabled
    
    dom_xss_enabled: bool = True  # Static analysis always; dynamic needs Chrome/Selenium
    execution_verify_firefox: bool = False  # Optional second-browser execution verification
    
    stored_xss_enabled: bool = True
    
    include_patterns: Optional[List[str]] = None  # URL paths to include (regex)
    exclude_patterns: Optional[List[str]] = None  # URL paths to exclude (regex)
    risk_prioritization: bool = True  # Prioritize likely-vulnerable endpoints first
    risk_priority_top_k: int = 300    # Optional cap for prioritized URL pool (0 = unlimited)
    
    payload_dir: str = "data/payloads"
    custom_payloads_file: Optional[str] = None
    
    output_dir: str = "output"
    report_format: str = "html"  # html, json, both
    verbose: bool = False
    quiet: bool = False
    
    threads: int = 10
    scan_budget_seconds: int = 0  # Hard cap for wall-clock scan duration (0 = unlimited)
    scan_budget_requests: int = 0  # Hard cap for total HTTP requests (0 = unlimited)
    scan_budget_payloads: int = 0  # Hard cap for total payload attempts (0 = unlimited)
    max_payloads_per_param: int = 0  # Hard cap per parameter payload attempts (0 = planner-defined)
    max_payloads_per_endpoint: int = 0  # Hard cap per endpoint payload attempts (0 = unlimited)
    budget_auto_fallback: bool = True  # Automatically degrade optional modules under high budget pressure
    budget_fallback_trigger: float = 0.85  # Budget utilization ratio that triggers fallback mode
    distributed_task_queue: bool = True  # Enable worker-friendly lease/ack task queue model
    dynamic_task_lease: bool = True  # Adapt task lease duration to observed task runtime
    task_lease_seconds: int = 120  # Lease duration for claimed tasks before requeue
    task_max_retries: int = 3  # Max retries for queue tasks before dead-letter failure
    task_worker_id: Optional[str] = None  # Explicit worker identity for distributed task claiming
    resume_checkpoint_interval_seconds: int = 20  # Periodic resume checkpoint cadence
    strict_scope_guard: bool = True  # Clamp risky full-scan settings to safe defaults
    scope_guard_max_pages: int = 5000  # Upper guardrail for max_pages when scope guard is enabled
    learning_enabled: bool = True
    learning_data_file: str = "data/learning/payload_stats.json"
    payload_failure_taxonomy: bool = True  # Track categorized failure reasons for payload learning
    payload_context_bandit: bool = True    # Use endpoint profile signals in UCB payload ranking
    payload_minimal_grammar: bool = True   # Prefer context-minimal grammar-guided payloads first
    payload_similarity_warm_start: bool = True  # Blend similarity-family history for cold-start mitigation
    ucb_exploration_factor: float = 1.4  # Exploration pressure in contextual UCB ranking
    payload_context_weight: float = 0.25  # Context profile contribution to payload ranking
    payload_encoding_weight: float = 0.15  # Encoding profile contribution to payload ranking
    payload_waf_confidence_weight: float = 0.10  # WAF confidence modulation strength
    payload_context_multipliers: Optional[Dict[str, float]] = None  # Optional context-specific ranking multipliers
    
    resume_file: Optional[str] = None  # Path to resume file for interrupted scans
    
    webhook_url: Optional[str] = None      # Discord/Slack/Telegram webhook URL
    webhook_platform: Optional[str] = None # 'discord' | 'slack' | 'telegram' | 'auto'
    telegram_chat_id: Optional[str] = None # Required for Telegram
    
    api_mode: bool = False  # Enable API endpoint scanning (JSON body XSS)

    test_post_methods: bool = False  # Test POST / JSON body parameters in addition to GET (default: GET-only)
    
    collaborator_url: Optional[str] = None  # External collaborator URL (Burp Collaborator, interactsh, webhook, etc.)
    oast_enabled: bool = False               # Enable built-in Interactsh OAST polling for Blind XSS
    
    encode_strategy: str = "auto"  # auto | all | url | double-url | html | html-hex | unicode | js-octal | base64 | mixed-case | null-byte | comment | none

    def apply_overrides(self, overrides: Dict[str, Any], *, ignore_none: bool = True) -> 'Config':
        """Apply runtime overrides (typically CLI args) onto current config."""
        if not overrides:
            return self
        valid_fields = set(self.__dataclass_fields__.keys())
        for key, value in overrides.items():
            if key not in valid_fields:
                continue
            if ignore_none and value is None:
                continue
            setattr(self, key, value)
        return self
    
    @classmethod
    def from_file(cls, config_file: str) -> 'Config':
        """Load configuration from YAML file"""
        with open(config_file, 'r') as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            raise ValueError("Config file must contain a YAML mapping at top level")
        
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)
    
    def to_file(self, config_file: str):
        """Save configuration to YAML file"""
        with open(config_file, 'w') as f:
            yaml.dump(self.__dict__, f, default_flow_style=False)
    
    @classmethod
    def default(cls) -> 'Config':
        """Get default configuration"""
        return cls()
