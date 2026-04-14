"""Regression tests for SmartValidator behavior."""

import unittest

from akha.smart_layer.validator import SmartValidator


class TestSmartValidator(unittest.TestCase):
    def test_raw_reflection_with_encoded_variants_is_real(self):
        sv = SmartValidator()
        payload = '<img src=x onerror=alert(1)>'
        body = (
            payload
            + " "
            + '&lt;img src=x onerror=alert(1)&gt;'
            + " "
            + '%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E'
        )

        self.assertTrue(sv.is_real_xss(body, payload, trusted_signal=False))


if __name__ == "__main__":
    unittest.main()
