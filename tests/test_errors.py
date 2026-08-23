import unittest

from pproxy.errors import (
    AuthenticationError,
    BlockedConnection,
    ConfigurationError,
    ConnectionClosed,
    ProtocolError,
    RequestError,
    UpstreamError,
    UnsupportedProtocol,
    require,
)


class ProtocolValidationTests(unittest.TestCase):
    def test_runtime_errors_have_distinct_compatibility_friendly_types(self):
        self.assertIsInstance(AuthenticationError(), ProtocolError)
        self.assertIsInstance(BlockedConnection(), ProtocolError)
        self.assertIsInstance(RequestError(), ProtocolError)
        self.assertIsInstance(UnsupportedProtocol(), ProtocolError)
        self.assertIsInstance(ConfigurationError(), ValueError)
        self.assertIsInstance(ConnectionClosed(), ConnectionError)
        self.assertIsInstance(UpstreamError(), ConnectionError)
        self.assertEqual(str(ConnectionClosed()), 'Connection closed')

    def test_require_preserves_assertion_error_compatibility(self):
        with self.assertRaises(ProtocolError) as context:
            require(False, "invalid frame")

        self.assertIsInstance(context.exception, AssertionError)
        self.assertEqual(str(context.exception), "invalid frame")

    def test_require_returns_without_changing_truthy_values(self):
        self.assertIsNone(require(True))


if __name__ == "__main__":
    unittest.main()
