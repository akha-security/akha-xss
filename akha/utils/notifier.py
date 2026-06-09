"""
Webhook notification module for real-time vulnerability alerts.
Supports Discord, Slack, and Telegram.
"""

import json
import re
import threading
from typing import Optional, Dict, List
from datetime import datetime

try:
    import requests as _requests
except ImportError:
    _requests = None


class Notifier:
    """Send vulnerability alerts to webhook endpoints"""

    PLATFORMS = ('discord', 'slack', 'telegram')

    def __init__(self, webhook_url: str, platform: str = 'auto',
                 telegram_chat_id: Optional[str] = None, quiet: bool = False):
        """
        Args:
            webhook_url: Webhook / bot-token URL
            platform: 'discord' | 'slack' | 'telegram' | 'auto'
            telegram_chat_id: Required when platform is telegram
            quiet: Suppress notifier errors
        """
        self.webhook_url = webhook_url.rstrip('/')
        self.platform = self._detect_platform(platform, webhook_url)
        self.telegram_chat_id = telegram_chat_id
        self.quiet = quiet
        self._lock = threading.Lock()
        self._sent = 0
        self._errors = 0

    def __repr__(self):
        return f"Notifier(platform={self.platform!r}, url=***)"

    def __str__(self):
        return self.__repr__()


    @staticmethod
    def _detect_platform(platform: str, url: str) -> str:
        if platform != 'auto':
            return platform.lower()
        low = url.lower()
        if 'discord.com/api/webhooks' in low or 'discordapp.com/api/webhooks' in low:
            return 'discord'
        if 'hooks.slack.com' in low:
            return 'slack'
        if 'api.telegram.org' in low:
            return 'telegram'
        return 'slack'


    def notify_vulnerability(self, vuln: Dict, target: str) -> bool:
        """Send a vulnerability alert (non-blocking)."""
        t = threading.Thread(target=self._send_vuln, args=(vuln, target), daemon=True)
        t.start()
        return True

    def notify_scan_start(self, target: str, mode: str) -> bool:
        title = "🎯 AKHA Scan Started"
        body = (
            f"**Target:** {target}\n"
            f"**Mode:** {mode.upper()}\n"
            f"**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        t = threading.Thread(
            target=self._send,
            args=(title, body),
            kwargs={'color': 0x3498DB},
            daemon=True,
        )
        t.start()
        return True  # blue

    def notify_scan_complete(self, target: str, stats: Dict,
                             vuln_count: int, duration: float) -> bool:
        title = "📊 AKHA Scan Complete"
        mins = int(duration) // 60
        secs = int(duration) % 60
        body = (
            f"**Target:** {target}\n"
            f"**Duration:** {mins}m {secs}s\n"
            f"**URLs Crawled:** {stats.get('urls_crawled', 0)}\n"
            f"**Parameters:** {stats.get('params_found', 0)}\n"
            f"**Payloads Tested:** {stats.get('payloads_tested', 0)}\n"
            f"**Vulnerabilities:** {vuln_count}"
        )
        color = 0xE74C3C if vuln_count > 0 else 0x2ECC71
        t = threading.Thread(
            target=self._send,
            args=(title, body),
            kwargs={'color': color},
            daemon=True,
        )
        t.start()
        return True

    @property
    def sent_count(self) -> int:
        return self._sent

    @property
    def error_count(self) -> int:
        return self._errors


    def _send_vuln(self, vuln: Dict, target: str):
        vuln_type = vuln.get('type', 'reflected').replace('_', ' ').title()
        confidence = vuln.get('confidence', 0)
        param = vuln.get('parameter', '?')
        url = vuln.get('url', target)
        payload = vuln.get('payload', '')
        if len(payload) > 200:
            payload = payload[:200] + '…'

        title = f"🚨 XSS Detected — {vuln_type}"
        body = (
            f"**Type:** {vuln_type}\n"
            f"**URL:** {url}\n"
            f"**Parameter:** {param}\n"
            f"**Confidence:** {confidence}%\n"
            f"**Payload:** `{payload}`"
        )
        self._send(title, body, color=0xE74C3C)

    def _send(self, title: str, body: str, color: int = 0xE74C3C) -> bool:
        if _requests is None:
            return False

        try:
            if self.platform == 'discord':
                return self._send_discord(title, body, color)
            elif self.platform == 'slack':
                return self._send_slack(title, body)
            elif self.platform == 'telegram':
                return self._send_telegram(title, body)
            return False
        except Exception as e:
            with self._lock:
                self._errors += 1
            if not self.quiet:
                print(f"[Notifier] Error: {e}")
            return False


    def _send_discord(self, title: str, body: str, color: int) -> bool:
        payload = {
            "embeds": [{
                "title": title,
                "description": body,
                "color": color,
                "footer": {"text": "AKHA XSS Scanner"},
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }]
        }
        r = _requests.post(self.webhook_url, json=payload, timeout=10)
        if r.status_code in (200, 204):
            with self._lock:
                self._sent += 1
            return True
        with self._lock:
            self._errors += 1
        return False


    def _send_slack(self, title: str, body: str) -> bool:
        slack_body = body.replace('**', '*')
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": title, "emoji": True}
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": slack_body}
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn",
                         "text": f"AKHA XSS Scanner • {datetime.now().strftime('%H:%M:%S')}"}
                    ]
                }
            ]
        }
        r = _requests.post(self.webhook_url, json=payload, timeout=10)
        if r.status_code == 200:
            with self._lock:
                self._sent += 1
            return True
        with self._lock:
            self._errors += 1
        return False


    def _send_telegram(self, title: str, body: str) -> bool:
        if not self.telegram_chat_id:
            return False

        text = f"<b>{title}</b>\n\n{body}"
        text = text.replace('**', '')
        text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)

        url = f"{self.webhook_url}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        r = _requests.post(url, json=payload, timeout=10)
        if r.status_code == 200:
            with self._lock:
                self._sent += 1
            return True
        with self._lock:
            self._errors += 1
        return False
