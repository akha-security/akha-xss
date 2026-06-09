"""
Plugin system for AKHA CLI.

Supports two discovery mechanisms:

    1. **Entry-points** — third-party packages register under the
       ``akha.plugins`` group in their ``setup.cfg`` / ``pyproject.toml``.
    2. **Directory** — drop a ``.py`` file into ``~/.akha/plugins/`` (or a
       custom path).  The file must expose a ``register(registry)`` function.

Each plugin can:
    • Add new CLI sub-commands (argument groups + handler).
    • Hook into scan lifecycle events (pre_scan, post_scan, on_finding).

Example plugin (``~/.akha/plugins/my_notify.py``)::

    from akha.cli.plugins import PluginBase

    class NotifyPlugin(PluginBase):
        name = "notify"
        description = "Send Slack notification on scan finish"

        def add_arguments(self, parser):
            parser.add_argument("--slack-token", help="Slack token")

        def on_finding(self, finding):
            ...

        def post_scan(self, results):
            ...

    def register(registry):
        registry.register(NotifyPlugin())
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import os
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type

logger = logging.getLogger("akha.plugins")

__all__ = [
    "PluginBase",
    "PluginRegistry",
]



class PluginBase(ABC):
    """Base class every AKHA plugin must inherit from."""

    name: str = ""
    description: str = ""
    version: str = "0.1.0"


    def add_arguments(self, parser) -> None:
        """Optional: Inject extra argparse arguments."""

    def handle(self, args) -> Optional[int]:
        """Optional: Handle a custom sub-command.  Return exit-code or None."""
        return None


    def pre_scan(self, config) -> None:
        """Called before scanning begins."""

    def post_scan(self, results: Dict[str, Any]) -> None:
        """Called after all targets have been scanned."""

    def on_finding(self, finding: Dict[str, Any]) -> None:
        """Called each time a vulnerability is confirmed."""




class PluginRegistry:
    """Central catalogue of loaded plugins."""

    def __init__(self) -> None:
        self._plugins: Dict[str, PluginBase] = {}


    def register(self, plugin: PluginBase) -> None:
        """Register a plugin instance."""
        if not plugin.name:
            logger.warning("Plugin has no name — skipping")
            return
        if plugin.name in self._plugins:
            logger.warning("Plugin '%s' already registered — skipping duplicate", plugin.name)
            return
        self._plugins[plugin.name] = plugin
        logger.debug("Registered plugin: %s (%s)", plugin.name, plugin.version)

    def get(self, name: str) -> Optional[PluginBase]:
        return self._plugins.get(name)

    @property
    def all(self) -> List[PluginBase]:
        return list(self._plugins.values())

    def __len__(self) -> int:
        return len(self._plugins)

    def __iter__(self):
        return iter(self._plugins.values())


    def auto_discover(self) -> None:
        """Discover plugins from entry-points and the default directory."""
        self._discover_entry_points()
        self._discover_directory()

    def _discover_entry_points(self) -> None:
        """Load plugins registered under the ``akha.plugins`` entry-point group."""
        try:
            if sys.version_info >= (3, 10):
                from importlib.metadata import entry_points
                eps = entry_points(group="akha.plugins")
            else:
                from importlib.metadata import entry_points as _eps
                all_eps = _eps()
                eps = all_eps.get("akha.plugins", [])

            for ep in eps:
                try:
                    obj = ep.load()
                    if callable(obj):
                        obj(self)  # expects register(registry)
                    logger.debug("Loaded entry-point plugin: %s", ep.name)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Failed to load plugin '%s': %s", ep.name, exc)
        except Exception:  # noqa: BLE001
            logger.debug("Entry-point discovery unavailable")

    def _discover_directory(self, path: Optional[str] = None) -> None:
        """Load ``*.py`` plugins from a directory."""
        plugin_dir = Path(path) if path else Path.home() / ".akha" / "plugins"
        if not plugin_dir.is_dir():
            return

        for py_file in sorted(plugin_dir.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    f"akha_plugin_{py_file.stem}", py_file,
                )
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    register_fn = getattr(mod, "register", None)
                    if callable(register_fn):
                        register_fn(self)
                        logger.debug("Loaded directory plugin: %s", py_file.name)
                    else:
                        logger.warning("Plugin '%s' has no register() function", py_file.name)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to load plugin '%s': %s", py_file.name, exc)


    def fire_pre_scan(self, config) -> None:
        for p in self._plugins.values():
            try:
                p.pre_scan(config)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Plugin '%s' pre_scan error: %s", p.name, exc)

    def fire_post_scan(self, results: Dict[str, Any]) -> None:
        for p in self._plugins.values():
            try:
                p.post_scan(results)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Plugin '%s' post_scan error: %s", p.name, exc)

    def fire_on_finding(self, finding: Dict[str, Any]) -> None:
        for p in self._plugins.values():
            try:
                p.on_finding(finding)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Plugin '%s' on_finding error: %s", p.name, exc)
