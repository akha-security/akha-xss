"""
Main entry point for AKHA Scanner CLI.

    python -m akha [COMMAND] [OPTIONS]
"""

import sys
import warnings

warnings.filterwarnings(
    "ignore",
    message="coroutine '.*' was never awaited",
    category=RuntimeWarning,
)

from akha.cli import main


def _entry() -> None:
    """Setuptools console_scripts entry-point."""
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)


if __name__ == "__main__":
    _entry()
