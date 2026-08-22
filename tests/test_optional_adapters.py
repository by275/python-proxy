import unittest

from pproxy import server
from pproxy.h2 import ProxyH2
from pproxy.ssh import ProxySSH


class OptionalAdapterTests(unittest.TestCase):
    def test_h2_adapter_keeps_server_compatibility_alias(self):
        self.assertIs(server.ProxyH2, ProxyH2)

    def test_ssh_adapter_keeps_server_compatibility_alias(self):
        self.assertIs(server.ProxySSH, ProxySSH)


if __name__ == "__main__":
    unittest.main()
