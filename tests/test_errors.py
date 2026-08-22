import unittest

from pproxy.errors import ProtocolError, require


class ProtocolValidationTests(unittest.TestCase):
    def test_require_preserves_assertion_error_compatibility(self):
        with self.assertRaises(ProtocolError) as context:
            require(False, "invalid frame")

        self.assertIsInstance(context.exception, AssertionError)
        self.assertEqual(str(context.exception), "invalid frame")

    def test_require_returns_without_changing_truthy_values(self):
        self.assertIsNone(require(True))


if __name__ == "__main__":
    unittest.main()
