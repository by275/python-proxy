"""Test optional HTTP/2, QUIC, and SSH adapter availability."""

import unittest

from pproxy import server
from pproxy.h2 import ProxyH2
from pproxy.quic import ProxyH3, ProxyQUIC
from pproxy.ssh import ProxySSH


class OptionalAdapterTests(unittest.TestCase):
    def test_h2_adapter_keeps_server_compatibility_alias(self):
        self.assertIs(server.ProxyH2, ProxyH2)

    def test_ssh_adapter_keeps_server_compatibility_alias(self):
        self.assertIs(server.ProxySSH, ProxySSH)

    def test_quic_adapters_keep_server_compatibility_aliases(self):
        self.assertIs(server.ProxyQUIC, ProxyQUIC)
        self.assertIs(server.ProxyH3, ProxyH3)


if __name__ == "__main__":
    unittest.main()
