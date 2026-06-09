import unittest

from akha.cli.base import build_parser
from akha.cli.handlers import handle_presets


class TestCliUtilityCommands(unittest.TestCase):
    def test_doctor_and_presets_commands_parse(self):
        parser = build_parser()

        self.assertEqual(parser.parse_args(["doctor"]).command, "doctor")
        self.assertEqual(parser.parse_args(["presets"]).command, "presets")

    def test_presets_handler_returns_success(self):
        self.assertEqual(handle_presets(None, None), 0)


if __name__ == "__main__":
    unittest.main()
