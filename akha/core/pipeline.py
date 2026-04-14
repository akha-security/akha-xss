"""
Pipeline components for scanner architecture separation.

Provides explicit collector/analyzer/exploiter/reporter responsibilities
without changing scanner external behavior.
"""

from __future__ import annotations

from typing import Dict, List, Optional


class ScanCollector:
    """Collects URLs and parameters from the target surface."""

    def __init__(self, crawler, param_finder, config):
        self.crawler = crawler
        self.param_finder = param_finder
        self.config = config


class ScanAnalyzer:
    """Runs analysis modules that classify risk and constraints."""

    def __init__(self, waf_detector, csp_analyzer):
        self.waf_detector = waf_detector
        self.csp_analyzer = csp_analyzer

    def detect_waf(self, target_url: str) -> Dict:
        return self.waf_detector.detect(target_url)

    def analyze_csp(self, target_url: str) -> Dict:
        return self.csp_analyzer.analyze(target_url)


class ScanExploiter:
    """Executes payload delivery and vulnerability probing."""

    def __init__(self, xss_engine):
        self.xss_engine = xss_engine

    def scan_reflected(self, url: str, params: List[Dict], waf_name: Optional[str], session=None) -> List[Dict]:
        return self.xss_engine.scan(url, params, waf_name, session=session)


class ScanReporter:
    """Generates output artifacts from normalized report data."""

    def __init__(self, config, html_generator_cls, json_generator_cls):
        self.config = config
        self._html_generator_cls = html_generator_cls
        self._json_generator_cls = json_generator_cls

    def generate(self, report_data: Dict) -> Dict[str, str]:
        paths: Dict[str, str] = {}
        fmt = self.config.report_format.lower()

        if fmt in ('html', 'both'):
            generator = self._html_generator_cls(self.config)
            paths['html'] = generator.generate(report_data)

        if fmt in ('json', 'both'):
            generator = self._json_generator_cls(self.config)
            paths['json'] = generator.generate(report_data)

        return paths
