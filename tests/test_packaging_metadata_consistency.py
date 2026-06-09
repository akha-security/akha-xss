"""Keep setup.py and pyproject.toml in sync for core package metadata."""

import re
import unittest
from pathlib import Path
import tomllib


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

    def test_browser_dependencies_are_mandatory(self):
        requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
        setup_text = (ROOT / "setup.py").read_text(encoding="utf-8").lower()
        pyproject_text = (ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()

        self.assertIn("playwright>=1.40.0", requirements)
        self.assertIn("selenium>=4.10.0", requirements)
        self.assertNotIn("extras_require", setup_text)
        self.assertNotIn("[project.optional-dependencies]", pyproject_text)
        self.assertIn("playwright>=1.40.0", pyproject_text)

    def test_pyproject_dependencies_match_requirements(self):
        requirements = [
            line.strip()
            for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

        self.assertEqual(requirements, pyproject["project"]["dependencies"])

    def test_mitmproxy_compatibility_pins_are_documented(self):
        compat_path = ROOT / "requirements-mitmproxy-compat.txt"
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        compat = compat_path.read_text(encoding="utf-8").lower()

        self.assertTrue(compat_path.is_file())
        self.assertIn("mitmproxy_rs>=0.12.6,<0.13", compat)
        self.assertIn("asgiref>=3.2.10,<=3.10.0", compat)
        self.assertIn("tornado>=6.5.0,<=6.5.2", compat)
        self.assertIn("urwid>=2.6.14,<=3.0.3", compat)
        self.assertIn("wsproto>=1.0,<=1.2.0", compat)
        self.assertIn("requirements-mitmproxy-compat.txt", readme)

    def test_package_data_patterns_point_to_existing_trees(self):
        pyproject_text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

        self.assertNotIn("reports/templates", pyproject_text)
        self.assertNotIn("data/learning", pyproject_text)
        self.assertTrue((ROOT / "akha" / "data" / "wordlists").is_dir())
        self.assertTrue((ROOT / "akha" / "data" / "waf_profiles").is_dir())


if __name__ == "__main__":
    unittest.main()
