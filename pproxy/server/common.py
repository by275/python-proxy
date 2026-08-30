"""Shared helpers for server construction and connection setup."""

import random
import re
import time
from typing import Any, Callable

from .. import transport
from ..errors import ConfigurationError


SOCKET_TIMEOUT = transport.DEFAULT_TIMEOUT


def DUMMY(value):  # pylint: disable=invalid-name  # public identity callback
    """Return a payload unchanged when no plugin transform is configured."""
    return value


class AuthTable:
    """Cache authenticated users for a remote address for a limited period."""

    def __init__(self, remote_ip, authtime):
        self.remote_ip = remote_ip
        self.authtime = authtime
        self._auth = {}
        self._user = {}

    def authed(self):
        """Return the cached user when its authentication window is valid."""
        if time.time() - self._auth.get(self.remote_ip, 0) <= self.authtime:
            return self._user[self.remote_ip]
        return None

    def set_authed(self, user):
        """Cache a successfully authenticated user for this remote address."""
        self._auth[self.remote_ip] = time.time()
        self._user[self.remote_ip] = user


async def prepare_ciphers(cipher, reader, writer, bind=None, server_side=True):
    """Create connection-local cipher and plugin state."""
    if cipher:
        cipher = cipher.for_connection()
        cipher.pdecrypt = cipher.pdecrypt2 = cipher.pencrypt = cipher.pencrypt2 = DUMMY
        for plugin in cipher.plugins:
            if server_side:
                await plugin.init_server_data(reader, writer, cipher, bind)
            else:
                await plugin.init_client_data(reader, writer, cipher)
            plugin.add_cipher(cipher)
        return cipher(
            reader, writer, cipher.pdecrypt, cipher.pdecrypt2,
            cipher.pencrypt, cipher.pencrypt2,
        )
    return None, None


def schedule(rserver, salgorithm, host_name, port):
    """Select an available remote according to the configured algorithm."""
    def filter_cond(option):
        """Return whether one remote is alive and matches the request."""
        return option.alive and option.match_rule(host_name, port)
    if salgorithm == 'fa':
        return next(filter(filter_cond, rserver), None)
    if salgorithm == 'rr':
        for index, option in enumerate(rserver):
            if filter_cond(option):
                rserver.append(rserver.pop(index))
                return option
    if salgorithm == 'rc':
        options = [option for option in rserver if filter_cond(option)]
        return random.choice(options) if options else None
    if salgorithm == 'lc':
        return min(
            filter(filter_cond, rserver),
            default=None,
            key=lambda option: option.connections,
        )
    raise ConfigurationError('Unknown scheduling algorithm')


def compile_rule(filename: str) -> Callable[[str], Any]:
    """Compile an inline rule or a newline-delimited rule file."""
    if filename.startswith("{") and filename.endswith("}"):
        return re.compile(filename[1:-1]).match
    with open(filename, encoding='utf-8') as rule_file:
        return re.compile(
            '(:?' + ''.join(
                '|'.join(
                    item.strip()
                    for item in rule_file
                    if item.strip() and not item.startswith('#')
                )
            ) + ')$'
        ).match


def split_uri_jumps(uri_jumps: str) -> list[str]:
    """Split chained proxy URIs while preserving URI contents."""
    parts = []
    start = 0
    for match in re.finditer(r'__(?=[A-Za-z][A-Za-z0-9+.-]*://)', uri_jumps):
        parts.append(uri_jumps[start:match.start()])
        start = match.end()
    parts.append(uri_jumps[start:])
    return parts
