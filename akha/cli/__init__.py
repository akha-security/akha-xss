"""
AKHA CLI package.

Entry-point: ``main()`` — builds the argparse parser, discovers plugins,
dispatches to the matching handler, and returns an exit-code.

Legacy Click interface is preserved in ``commands.py`` for backward
compatibility (``akha.cli.commands.cli``).
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence

from akha.cli.base import build_parser
from akha.cli.handlers import handle_payloads, handle_scan, handle_stats
from akha.cli.output import print_banner, print_error, print_root_short_help, print_welcome_screen
from akha.cli.plugins import PluginRegistry

__all__ = ["main"]


_original_unraisablehook = sys.unraisablehook

def _quiet_unraisable(unraisable):
    exc = unraisable.exc_value
    if isinstance(exc, RuntimeError) and "Event loop is closed" in str(exc):
        return  # swallow silently
    _original_unraisablehook(unraisable)

sys.unraisablehook = _quiet_unraisable

import logging as _logging
_logging.getLogger("asyncio").setLevel(_logging.CRITICAL)


def _get_subparser(parser: argparse.ArgumentParser, name: str):
    """Return named subparser (e.g. 'scan') if present."""
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict) and name in choices:
            return choices[name]
    return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry-point.  Returns an integer exit-code."""

    registry = PluginRegistry()
    registry.auto_discover()

    parser = build_parser(registry=registry)

    raw_argv = list(argv) if argv is not None else sys.argv[1:]

    if not raw_argv:
        print_welcome_screen()
        return 0

    if raw_argv == ["-h"]:
        print_banner()
        print_root_short_help()
        return 0

    if raw_argv == ["--help"]:
        print_banner()
        parser.print_help()
        scan_parser = _get_subparser(parser, "scan")
        if scan_parser is not None:
            print()
            print("Detailed scan options:")
            scan_parser.print_help()
        return 0

    args = parser.parse_args(raw_argv)

    if not args.command:
        print_error("No command selected. Use 'akha-xss --help' to see commands.")
        parser.print_help()
        return 1

    handler_map = {
        "scan": handle_scan,
        "payloads": handle_payloads,
        "stats": handle_stats,
    }

    handler = handler_map.get(args.command)

    if handler is None:
        for plugin in registry:
            if plugin.name == args.command:
                rc = plugin.handle(args)
                return rc if rc is not None else 0

    if handler is None:
        print_error(f"Unknown command: {args.command}")
        parser.print_help()
        return 1

    try:
        return handler(args, registry)
    except KeyboardInterrupt:
        print_error("Interrupted by user.")
        return 130
    except Exception as exc:
        print_error(f"Fatal error: {exc}")
        if getattr(args, "verbose", False):
            import traceback
            traceback.print_exc()
        return 1
