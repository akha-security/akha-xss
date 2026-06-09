"""
Legacy Click CLI — backward-compatibility shim.

The canonical CLI is now in ``akha.cli`` (argparse-based).
This module preserves the ``cli`` callable so that existing
``setup.py`` entry-points or scripts that import
``from akha.cli.commands import cli`` continue to work.

It simply delegates to the new argparse entry-point.
"""

from __future__ import annotations

import sys


def cli(args=None):
    """Click-compatible entry-point that forwards to the argparse CLI."""
    from akha.cli import main
    raise SystemExit(main(args))


if __name__ == "__main__":
    cli()

