"""Test optional HTTP/2, QUIC, and SSH adapter availability."""

import unittest

from pproxy import server
from pproxy.h2 import ProxyH2
from pproxy.quic import ProxyH3, ProxyQUIC
from pproxy.runtime import OptionalAdapter, require_optional_adapter
from pproxy.ssh import ProxySSH


class OptionalAdapterTests(unittest.TestCase):
    def test_optional_adapters_implement_the_lifecycle_contract(self):
        expected = {
            ProxyH2: ('h2', 'h2', False),
            ProxyQUIC: ('quic', 'aioquic', True),
            ProxyH3: ('h3', 'aioquic', True),
            ProxySSH: ('ssh', 'asyncssh', False),
        }

        for adapter_class, (name, dependency, datagrams) in expected.items():
            with self.subTest(adapter=adapter_class.__name__):
                adapter = adapter_class.__new__(adapter_class)
                self.assertIsInstance(adapter, OptionalAdapter)
                self.assertIs(require_optional_adapter(adapter), adapter)
                self.assertEqual(adapter.adapter_capabilities.name, name)
                self.assertEqual(adapter.adapter_capabilities.dependency, dependency)
                self.assertEqual(adapter.adapter_capabilities.supports_datagrams, datagrams)
                self.assertTrue(adapter.adapter_capabilities.supports_streams)
                self.assertTrue(adapter.adapter_capabilities.multiplexed)
                self.assertTrue(adapter.adapter_capabilities.owns_shared_session)

    def test_contract_validation_rejects_incomplete_objects(self):
        with self.assertRaises(TypeError):
            require_optional_adapter(object())

        class InvalidCapabilities:
            adapter_capabilities = object()

            def close(self):
                return None

            async def wait_closed(self):
                return None

            async def aclose(self):
                return None

            async def wait_open_connection(self, _host, _port, _local_addr, _family):
                return None, None

        with self.assertRaises(TypeError):
            require_optional_adapter(InvalidCapabilities())

    def test_h2_adapter_keeps_server_compatibility_alias(self):
        self.assertIs(server.ProxyH2, ProxyH2)

    def test_ssh_adapter_keeps_server_compatibility_alias(self):
        self.assertIs(server.ProxySSH, ProxySSH)

    def test_quic_adapters_keep_server_compatibility_aliases(self):
        self.assertIs(server.ProxyQUIC, ProxyQUIC)
        self.assertIs(server.ProxyH3, ProxyH3)


if __name__ == "__main__":
    unittest.main()
