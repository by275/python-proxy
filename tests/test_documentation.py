"""Keep user-facing documentation aligned with runtime contracts."""

import unittest
from pathlib import Path

import tomllib

from pproxy import proto


class DocumentationContractTests(unittest.TestCase):
    """Check the stable installation, protocol, and API documentation claims."""

    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.readme = (cls.root / 'README.rst').read_text()
        cls.changelog = (cls.root / 'CHANGELOG.md').read_text()
        cls.runtime_api = (cls.root / 'docs/RUNTIME_API.md').read_text()
        cls.security_policy = (cls.root / 'docs/SECURITY_POLICY.md').read_text()

    def test_readme_declares_supported_installation(self):
        self.assertIn('Python 3.12 or newer', self.readme)
        self.assertIn('git+https://github.com/by275/python-proxy.git', self.readme)
        self.assertIn('pproxy[h2,sshtunnel,quic]', self.readme)
        self.assertIn('ghcr.io/by275/pproxy:latest', self.readme)

    def test_readme_lists_every_non_modifier_protocol(self):
        for name, metadata in proto.PROTOCOL_METADATA.items():
            if not metadata.transport_modifier:
                with self.subTest(protocol=name):
                    self.assertIn(f'``{name}``', self.readme)

    def test_lifecycle_and_logging_docs_are_linked_and_recorded(self):
        self.assertIn('docs/RUNTIME_API.md', self.readme)
        self.assertIn('lifecycle', self.runtime_api.lower())
        self.assertIn('structured logging', self.runtime_api.lower())
        self.assertIn('lifecycle', self.changelog.lower())

    def test_security_policy_matches_cipher_documentation(self):
        self.assertIn('docs/SECURITY_POLICY.md', self.readme)
        for name in ('rc4', 'rc4-md5', 'bf-cfb', 'cast5-cfb', 'des-cfb'):
            with self.subTest(cipher=name):
                self.assertIn(f'`{name}`', self.security_policy)
        self.assertIn('chacha20-ietf-poly1305', self.security_policy)
        self.assertIn('There is no scheduled removal release', self.security_policy)

    def test_project_repository_metadata_matches_installation_docs(self):
        with (self.root / 'pyproject.toml').open('rb') as pyproject_file:
            project = tomllib.load(pyproject_file)['project']

        self.assertEqual(
            project['urls']['Repository'],
            'https://github.com/by275/python-proxy',
        )


if __name__ == '__main__':
    unittest.main()
