"""Proxy URI parsing and runtime object construction."""

# Optional backends and cycle-sensitive facades are intentionally imported at
# the point where their URI scheme is selected.
# pylint: disable=import-outside-toplevel

import argparse
import base64
import binascii
import importlib
import urllib.parse
from typing import Any

from .. import proto
from ..config import ProxyConfig
from ..errors import ConfigurationError
from .common import SOCKET_TIMEOUT, split_uri_jumps
from .connections import DIRECT, ProxyBackward, ProxyDirect, ProxySimple


sslcontexts = []


def proxies_by_uri(uri_jumps: str) -> Any:
    """Build a proxy object from a possibly chained proxy URI."""
    jump = DIRECT
    for uri in reversed(split_uri_jumps(uri_jumps)):
        jump = proxy_by_uri(uri, jump)
    return jump


def _configure_tls(rawprotos):
    if not ('ssl' in rawprotos or 'secure' in rawprotos or 'cfp' in rawprotos):
        return None, None
    import ssl

    sslserver = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    sslclient = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if 'ssl' in rawprotos or 'insecure' in rawprotos:
        sslclient.check_hostname = False
        sslclient.verify_mode = ssl.CERT_NONE
    sslcontexts.append(sslserver)
    sslcontexts.append(sslclient)
    return sslserver, sslclient


def _configure_quic(rawprotos, protonames):
    if 'quic' not in rawprotos and 'h3' not in protonames:
        return None, None
    try:
        import ssl
        import aioquic.quic.configuration
    except ImportError:
        raise ConfigurationError('Missing library: "pip3 install aioquic"') from None
    quicserver = aioquic.quic.configuration.QuicConfiguration(
        is_client=False,
        max_stream_data=2**60,
        max_data=2**60,
        idle_timeout=SOCKET_TIMEOUT,
    )
    quicclient = aioquic.quic.configuration.QuicConfiguration(
        max_stream_data=2**60,
        max_data=2**60,
        idle_timeout=SOCKET_TIMEOUT * 5,
    )
    quicclient.verify_mode = ssl.CERT_NONE if 'ssl' in rawprotos else ssl.CERT_REQUIRED
    sslcontexts.append(quicserver)
    sslcontexts.append(quicclient)
    return quicserver, quicclient


def _require_h2(rawprotos):
    if 'h2' not in rawprotos:
        return
    try:
        importlib.import_module('h2')
    except ImportError:
        raise ConfigurationError('Missing library: "pip3 install h2"') from None


def _parse_cipher(url):
    cipher, _, loc = url.netloc.rpartition('@')
    if not cipher:
        return None, loc
    from ..cipher import get_cipher

    if ':' not in cipher:
        try:
            cipher = base64.b64decode(cipher).decode()
        except (ValueError, UnicodeError, binascii.Error):
            pass
        if ':' not in cipher:
            raise argparse.ArgumentTypeError('userinfo must be "cipher:key"')
    err_str, cipher = get_cipher(cipher)
    if err_str:
        raise argparse.ArgumentTypeError(err_str)
    return cipher, loc


def _parse_users(url):
    if url.fragment.startswith('#'):
        with open(url.fragment[1:], encoding='utf-8') as auth_file:
            auth = auth_file.read().rstrip().encode()
    else:
        auth = url.fragment.encode()
    return [item.rstrip() for item in auth.split(b'\n')] if auth else None


def _parse_proxy_values(url, rawprotos, protonames):
    urlpath, _, plugins = url.path.partition(',')
    urlpath, _, lbind = urlpath.partition('@')
    plugins = plugins.split(',') if plugins else None
    cipher, loc = _parse_cipher(url)
    if cipher and plugins:
        from ..plugin import get_plugin

        for name in plugins:
            if not name:
                continue
            err_str, plugin = get_plugin(name)
            if err_str:
                raise argparse.ArgumentTypeError(err_str)
            cipher.plugins.append(plugin)
    if loc:
        host_name, port = proto.netloc_split(
            loc,
            default_host='127.0.0.1' if 'httpadmin' in protonames else None,
            default_port=22 if 'ssh' in rawprotos else 443 if 'cfp' in rawprotos else 8080,
        )
    else:
        host_name = port = None
    users = _parse_users(url)
    if 'httpadmin' in protonames and not users:
        raise argparse.ArgumentTypeError('httpadmin requires credentials in the URI fragment')
    return {
        'urlpath': urlpath,
        'lbind': lbind,
        'cipher': cipher,
        'loc': loc,
        'host_name': host_name,
        'port': port,
        'users': users,
    }


def _build_proxy(rawprotos, protonames, params, quicserver, quicclient):
    if 'quic' in rawprotos:
        from ..quic import ProxyQUIC

        proxy = ProxyQUIC(quicserver, quicclient, **params)
    elif 'h3' in protonames:
        from ..quic import ProxyH3

        proxy = ProxyH3(quicserver, quicclient, **params)
    elif 'h2' in rawprotos:
        from ..h2 import ProxyH2

        proxy = ProxyH2(**params)
    elif 'ssh' in protonames:
        from ..ssh import ProxySSH

        proxy = ProxySSH(**params)
    else:
        proxy = ProxySimple(**params)
    if 'in' in rawprotos:
        proxy = ProxyBackward(proxy, rawprotos.count('in'), **params)
    return proxy


def proxy_by_uri(uri: str, jump: Any) -> Any:
    """Build one proxy layer and attach *jump* as its downstream target."""
    scheme, _, uri = uri.partition('://')
    url = urllib.parse.urlparse('s://' + uri)
    rawprotos = [item.lower() for item in scheme.split('+')]
    err_str, protos = proto.get_protos(rawprotos)
    if err_str:
        raise argparse.ArgumentTypeError(err_str)
    protonames = [item.name for item in protos]
    sslserver, sslclient = _configure_tls(rawprotos)
    quicserver, quicclient = _configure_quic(rawprotos, protonames)
    _require_h2(rawprotos)
    values = _parse_proxy_values(url, rawprotos, protonames)
    if 'direct' in protonames:
        return ProxyDirect(lbind=values['lbind'])

    params = ProxyConfig(
        jump=jump,
        protos=protos,
        cipher=values['cipher'],
        users=values['users'],
        rule=url.query,
        bind=values['loc'] or values['urlpath'],
        host_name=values['host_name'],
        port=values['port'],
        unix=not values['loc'],
        lbind=values['lbind'],
        sslclient=sslclient,
        sslserver=sslserver,
        insecure_host_key='insecure' in rawprotos and 'ssh' in rawprotos,
    ).as_kwargs()
    return _build_proxy(rawprotos, protonames, params, quicserver, quicclient)
