"""Verify that optional dependency ranges remain synchronized."""

import re
import unittest
from pathlib import Path

import tomllib


class OptionalDependencyContractTests(unittest.TestCase):
    """Keep CI constraints aligned with the optional extras in pyproject.toml."""

    def test_optional_constraints_match_declared_extra_ranges(self):
        root = Path(__file__).resolve().parents[1]
        with (root / 'pyproject.toml').open('rb') as pyproject_file:
            project = tomllib.load(pyproject_file)

        extras = project['project']['optional-dependencies']
        expected = {
            'h2': 'h2>=4.0,<5',
            'sshtunnel': 'asyncssh>=2.5.0,<3',
            'quic': 'aioquic>=0.9.7,<2',
            'pycryptodome': 'pycryptodome>=3.7.2,<4',
            'uvloop': 'uvloop>=0.13.0,<1',
        }
        constraints = {
            re.split(r'[<>=!~]', line, maxsplit=1)[0]: line
            for line in (root / 'constraints/optional.txt').read_text().splitlines()
            if line and not line.startswith('#')
        }

        for requirement in expected.values():
            with self.subTest(requirement=requirement):
                extra_requirements = [
                    req.split(';', 1)[0].strip()
                    for requirements in extras.values()
                    for req in requirements
                ]
                self.assertIn(requirement, extra_requirements)
                package_name = re.split(r'[<>=!~]', requirement, maxsplit=1)[0]
                self.assertEqual(constraints.get(package_name), requirement)


if __name__ == '__main__':
    unittest.main()
