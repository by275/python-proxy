"""Test proxy configuration parsing and validation."""

import unittest

from pproxy.config import ProxyConfig


class ProxyConfigTests(unittest.TestCase):
    def test_constructor_kwargs_preserve_field_names(self):
        config = ProxyConfig(
            jump="direct",
            protos=["http"],
            cipher=None,
            users=None,
            rule=None,
            bind=":8080",
            host_name=None,
            port=8080,
            unix=False,
            lbind=None,
            sslclient=None,
            sslserver=None,
        )

        self.assertEqual(config.as_kwargs()["bind"], ":8080")
        self.assertEqual(config.as_kwargs()["protos"], ["http"])

    def test_config_is_immutable(self):
        config = ProxyConfig(
            "direct", [], None, None, None, ":8080", None, 8080, False, None, None, None
        )

        with self.assertRaises(AttributeError):
            config.port = 9000


if __name__ == "__main__":
    unittest.main()
