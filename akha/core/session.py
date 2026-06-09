"""
Scan session management with save/restore support
"""

import time
import json
import os
import hashlib
import threading
import re
from typing import Dict, List
from datetime import datetime


class Session:
    """Scan session tracker with resume capability (thread-safe)"""
    
    def __init__(self, target: str, scan_mode: str):
        self.target = target
        self.scan_mode = scan_mode
        self.start_time = time.time()
        self.end_time = None
        
        self._lock = threading.Lock()
        
        self.statistics = {
            'urls_crawled': 0,
            'params_found': 0,
            'payloads_tested': 0,
            'vulnerabilities_found': 0,
            'requests_sent': 0,
            'errors': 0,
        }
        
        self.vulnerabilities = []
        self.errors = []
        self._vuln_fingerprints = set()
        
        self.tested_params = set()  # Track which (url, param) combinations have been tested
        self.crawled_urls_data = []  # Store crawled URL data for resume
        self.task_queue_state = {}  # Serialized task queue snapshot for resumable workers
        self._interrupted = False

    @staticmethod
    def _make_key(url: str, param_name: str, location: str = "") -> str:
        raw = f"{url}|{param_name}|{location}"
        return hashlib.sha1(raw.encode('utf-8'), usedforsecurity=False).hexdigest()

    @staticmethod
    def _normalize_payload(payload: str) -> str:
        if not payload:
            return ""
        value = str(payload).lower()
        value = re.sub(r"\s+", "", value)
        value = re.sub(r"data-akha-id=\"[a-z0-9]+\"", "data-akha-id=", value)
        value = re.sub(r"akha_trace=[^&\s]+", "akha_trace=", value)
        value = re.sub(r"akha_stored[:_a-z0-9|-]+", "akha_stored", value)
        value = value.replace("class=akha", "class=")
        return value

    def _vuln_fingerprint(self, vuln: Dict) -> str:
        url = str(vuln.get('url', '') or '')
        param = str(vuln.get('parameter', '') or '')
        vtype = str(vuln.get('type', '') or '')
        payload = self._normalize_payload(vuln.get('payload', ''))
        context = vuln.get('context') or {}
        ctx_type = str(context.get('Type', '') or '')
        raw = f"{url}|{param}|{vtype}|{ctx_type}|{payload}"
        return hashlib.sha1(raw.encode('utf-8'), usedforsecurity=False).hexdigest()
        
    def add_vulnerability(self, vuln: Dict):
        """Add vulnerability to session (thread-safe)"""
        with self._lock:
            fp = self._vuln_fingerprint(vuln)
            if fp in self._vuln_fingerprints:
                return
            self._vuln_fingerprints.add(fp)
            self.vulnerabilities.append(vuln)
            self.statistics['vulnerabilities_found'] += 1
    
    def add_error(self, error: str):
        """Add error to session (thread-safe)"""
        with self._lock:
            self.errors.append({
                'timestamp': datetime.now().isoformat(),
                'error': error,
            })
            self.statistics['errors'] += 1
    
    def increment_stat(self, stat_name: str, value: int = 1):
        """Increment statistic (thread-safe)"""
        with self._lock:
            if stat_name in self.statistics:
                self.statistics[stat_name] += value
    
    def mark_tested(self, url: str, param_name: str, location: str = None):
        """Mark a URL+param(+location) as tested (thread-safe, for resume)."""
        with self._lock:
            key = self._make_key(url, param_name, location or '')
            self.tested_params.add(key)
    
    def is_tested(self, url: str, param_name: str, location: str = None) -> bool:
        """Check if URL+param(+location) has been tested (thread-safe)."""
        with self._lock:
            key = self._make_key(url, param_name, location or '')
            return key in self.tested_params
    
    def set_crawled_urls_data(self, data: List):
        """Set crawled URL data (thread-safe)."""
        with self._lock:
            self.crawled_urls_data = list(data)
    
    def get_crawled_urls_data(self) -> List:
        """Get crawled URL data (thread-safe)."""
        with self._lock:
            return list(self.crawled_urls_data)

    def set_task_queue_state(self, state: Dict):
        """Set serialized task queue state for distributed/resumable scans."""
        with self._lock:
            self.task_queue_state = dict(state or {})

    def get_task_queue_state(self) -> Dict:
        """Get task queue state snapshot (thread-safe copy)."""
        with self._lock:
            return dict(self.task_queue_state or {})
    
    def end(self):
        """End session"""
        self.end_time = time.time()
    
    def get_duration(self) -> float:
        """Get session duration in seconds"""
        end = self.end_time or time.time()
        return end - self.start_time
    
    def to_dict(self) -> Dict:
        """Convert session to dictionary (thread-safe)."""
        with self._lock:
            return {
                'target': self.target,
                'scan_mode': self.scan_mode,
                'start_time': self.start_time,
                'end_time': self.end_time,
                'duration': self.get_duration(),
                'statistics': dict(self.statistics),
                'vulnerabilities': list(self.vulnerabilities),
                'errors': list(self.errors),
                'tested_params': list(self.tested_params),
                'crawled_urls_data': list(self.crawled_urls_data),
                'task_queue_state': dict(self.task_queue_state),
            }
    
    def save(self, filepath: str):
        """Save session to file for resume"""
        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else '.', exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
    
    def save_resume_state(self, output_dir: str) -> str:
        """Save session state for resume after interruption"""
        resume_path = os.path.join(output_dir, 'resume', 'scan_state.json')
        os.makedirs(os.path.dirname(resume_path), exist_ok=True)
        self.save(resume_path)
        return resume_path
    
    @classmethod
    def restore(cls, filepath: str) -> 'Session':
        """Restore session from file"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        session = cls(data['target'], data['scan_mode'])
        session.statistics = data.get('statistics', session.statistics)
        session.vulnerabilities = data.get('vulnerabilities', [])
        session.errors = data.get('errors', [])
        session.tested_params = set(data.get('tested_params', []))
        session.crawled_urls_data = data.get('crawled_urls_data', [])
        session.task_queue_state = data.get('task_queue_state', {}) or {}
        session.start_time = data.get('start_time', session.start_time)
        for vuln in session.vulnerabilities:
            try:
                session._vuln_fingerprints.add(session._vuln_fingerprint(vuln))
            except Exception:
                continue
        
        return session
