"""
Built-in Interactsh OAST client for automatic Blind XSS detection.

Generates unique interaction URLs, polls the Interactsh server for
callbacks, and reports any triggered Blind XSS payloads back to the
scanner in real-time.
"""

import time
import uuid
import random
import string
import threading
import logging
from typing import Optional, List, Dict, Callable
from urllib.parse import urlparse

logger = logging.getLogger("akha.interactsh")


class InteractshClient:
    """Lightweight Interactsh OAST client for Blind XSS callback detection.

    Usage:
        client = InteractshClient()
        if client.register():
            url = client.get_interaction_url()
            # ... inject url as blind XSS payload ...
            hits = client.poll()
            for hit in hits:
                print(f"Blind XSS triggered from {hit['remote_address']}")
        client.close()
    """

    DEFAULT_SERVER = "https://oast.pro"
    POLL_INTERVAL = 5  # seconds between polls

    def __init__(self, server_url: Optional[str] = None, token: Optional[str] = None):
        self._server = (server_url or self.DEFAULT_SERVER).rstrip('/')
        self._token = token
        self._correlation_id: Optional[str] = None
        self._secret: Optional[str] = None
        self._registered = False
        self._poll_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._callbacks: List[Dict] = []
        self._callbacks_lock = threading.Lock()
        self._on_interaction: Optional[Callable] = None

    @property
    def registered(self) -> bool:
        return self._registered

    @property
    def interaction_url(self) -> Optional[str]:
        """Return the base interaction URL (inject this as blind XSS payload)."""
        if not self._correlation_id:
            return None
        parsed = urlparse(self._server)
        host = parsed.netloc or parsed.path
        return f"{self._correlation_id}.{host}"

    def register(self) -> bool:
        """Register with the Interactsh server and obtain a correlation ID.

        Returns True on success, False otherwise.
        """
        try:
            import requests as _req

            self._correlation_id = self._generate_correlation_id()
            self._secret = self._generate_secret()

            # Try to register with the server
            register_url = f"{self._server}/register"
            payload = {
                "public-key": self._correlation_id,
                "secret-key": self._secret,
                "correlation-id": self._correlation_id,
            }

            try:
                resp = _req.post(register_url, json=payload, timeout=10, verify=True)
                if resp.status_code in (200, 201):
                    self._registered = True
                    logger.info(
                        "Interactsh registered: %s.%s",
                        self._correlation_id,
                        urlparse(self._server).netloc,
                    )
                    return True
            except Exception:
                # If registration endpoint doesn't work (older server),
                # fall back to just using correlation-based polling
                pass

            # Fallback: many interactsh servers work without explicit registration
            self._registered = True
            logger.info(
                "Interactsh correlation ID ready: %s (server: %s)",
                self._correlation_id,
                self._server,
            )
            return True

        except ImportError:
            logger.warning("requests library not available for Interactsh")
            return False
        except Exception as e:
            logger.error("Interactsh registration failed: %s", e)
            return False

    def get_interaction_url(self, unique_tag: Optional[str] = None) -> str:
        """Generate a unique interaction URL for a specific injection point.

        Args:
            unique_tag: Optional tag to identify which injection triggered the callback.

        Returns:
            Full URL like: https://<tag>.<correlation_id>.<server_host>
        """
        if not self._correlation_id:
            raise RuntimeError("InteractshClient not registered")

        parsed = urlparse(self._server)
        host = parsed.netloc or parsed.path
        scheme = parsed.scheme or 'https'

        if unique_tag:
            # Sanitize tag
            tag = ''.join(c for c in unique_tag[:20] if c.isalnum() or c == '-').lower()
            return f"{scheme}://{tag}.{self._correlation_id}.{host}"
        return f"{scheme}://{self._correlation_id}.{host}"

    def get_payload_snippet(self, unique_tag: Optional[str] = None) -> str:
        """Return a ready-to-inject blind XSS payload using the OAST URL.

        Example output:
            <script src=https://abc123.xxxxx.oast.pro></script>
        """
        url = self.get_interaction_url(unique_tag)
        return f'"><script src={url}></script>'

    def start_polling(self, on_interaction: Optional[Callable] = None,
                      interval: int = None):
        """Start background polling thread.

        Args:
            on_interaction: Callback function(hit_dict) called for each new interaction.
            interval: Polling interval in seconds (default: 5).
        """
        if self._poll_thread and self._poll_thread.is_alive():
            return

        self._on_interaction = on_interaction
        self._stop_event.clear()
        self._poll_thread = threading.Thread(
            target=self._poll_loop,
            args=(interval or self.POLL_INTERVAL,),
            daemon=True,
            name="akha-interactsh-poll",
        )
        self._poll_thread.start()
        logger.info("Interactsh polling started (interval: %ds)", interval or self.POLL_INTERVAL)

    def stop_polling(self):
        """Stop background polling."""
        self._stop_event.set()
        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=10)
        self._poll_thread = None

    def poll(self) -> List[Dict]:
        """Manually poll the Interactsh server for new interactions.

        Returns:
            List of interaction dicts with keys like:
            - protocol: 'http' | 'dns' | 'smtp'
            - remote_address: source IP
            - timestamp: when it happened
            - raw_request: the full HTTP request (for HTTP interactions)
            - unique_id: sub-domain tag if present
        """
        if not self._registered or not self._correlation_id:
            return []

        try:
            import requests as _req

            poll_url = f"{self._server}/poll"
            params = {
                "id": self._correlation_id,
                "secret": self._secret or "",
            }

            resp = _req.get(poll_url, params=params, timeout=10, verify=True)
            if resp.status_code != 200:
                return []

            data = resp.json()
            interactions = data.get("data", []) or data.get("interactions", [])
            if not interactions:
                return []

            hits = []
            for item in interactions:
                hit = {
                    'protocol': item.get('protocol', 'unknown'),
                    'remote_address': item.get('remote-address', item.get('remote_address', 'unknown')),
                    'timestamp': item.get('timestamp', ''),
                    'raw_request': item.get('raw-request', item.get('raw_request', '')),
                    'unique_id': item.get('unique-id', item.get('unique_id', '')),
                    'full_id': item.get('full-id', item.get('full_id', '')),
                    'type': 'blind_xss_callback',
                }
                hits.append(hit)

            with self._callbacks_lock:
                self._callbacks.extend(hits)

            return hits

        except Exception as e:
            logger.debug("Interactsh poll error: %s", e)
            return []

    def get_all_callbacks(self) -> List[Dict]:
        """Return all callbacks received so far."""
        with self._callbacks_lock:
            return list(self._callbacks)

    def close(self):
        """Deregister from Interactsh server and stop polling."""
        self.stop_polling()

        if not self._registered:
            return

        try:
            import requests as _req
            deregister_url = f"{self._server}/deregister"
            payload = {
                "correlation-id": self._correlation_id,
                "secret-key": self._secret or "",
            }
            _req.post(deregister_url, json=payload, timeout=5, verify=True)
            logger.info("Interactsh deregistered: %s", self._correlation_id)
        except Exception:
            logger.debug("Interactsh deregistration failed", exc_info=True)
        finally:
            self._registered = False

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    def _poll_loop(self, interval: int):
        """Background polling loop."""
        while not self._stop_event.is_set():
            try:
                hits = self.poll()
                if hits and self._on_interaction:
                    for hit in hits:
                        try:
                            self._on_interaction(hit)
                        except Exception:
                            logger.debug("Interaction callback error", exc_info=True)
            except Exception:
                logger.debug("Poll loop error", exc_info=True)

            self._stop_event.wait(timeout=interval)

    @staticmethod
    def _generate_correlation_id() -> str:
        """Generate a 20-char lowercase alphanumeric correlation ID."""
        chars = string.ascii_lowercase + string.digits
        return ''.join(random.choices(chars, k=20))

    @staticmethod
    def _generate_secret() -> str:
        """Generate a random secret key."""
        return uuid.uuid4().hex[:16]
