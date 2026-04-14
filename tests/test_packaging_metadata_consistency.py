"""Keep setup.py and pyproject.toml in sync for core package metadata."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _extract(pattern: str, text: str) -> str:
    m = re.search(pattern, text, flags=re.MULTILINE)
    if not m:
        raise AssertionError(f"Pattern not found: {pattern}")
    return m.group(1)


class TestPackagingMetadataConsistency(unittest.TestCase):
    def test_setup_and_pyproject_core_fields_match(self):
        setup_text = (ROOT / "setup.py").read_text(encoding="utf-8")
        pyproject_text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

        setup_name = _extract(r'\bname\s*=\s*"([^"]+)"', setup_text)
        setup_version = _extract(r'\bversion\s*=\s*"([^"]+)"', setup_text)
        setup_url = _extract(r'\burl\s*=\s*"([^"]+)"', setup_text)

        py_name = _extract(r'^name\s*=\s*"([^"]+)"', pyproject_text)
        py_version = _extract(r'^version\s*=\s*"([^"]+)"', pyproject_text)
        py_homepage = _extract(r'^"Homepage"\s*=\s*"([^"]+)"', pyproject_text)

        self.assertEqual(setup_name, py_name)
        self.assertEqual(setup_version, py_version)
        self.assertEqual(setup_url, py_homepage)


if __name__ == "__main__":
    unittest.main()
