"""Proxy URI parsing and runtime object construction."""

import argparse
import base64
import binascii
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


def proxy_by_uri(uri: str, jump: Any) -> Any:
    """Build one proxy layer and attach *jump* as its downstream target."""
    scheme, _, uri = uri.partition('://')
    url = urllib.parse.urlparse('s://' + uri)
    rawprotos = [item.lower() for item in scheme.split('+')]
    err_str, protos = proto.get_protos(rawprotos)
    protonames = [item.name for item in protos]
    if err_str:
        raise argparse.ArgumentTypeError(err_str)
    if 'ssl' in rawprotos or 'secure' in rawprotos or 'cfp' in rawprotos:
        import ssl

        sslserver = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        sslclient = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if 'ssl' in rawprotos or 'insecure' in rawprotos:
            sslclient.check_hostname = False
            sslclient.verify_mode = ssl.CERT_NONE
        sslcontexts.append(sslserver)
        sslcontexts.append(sslclient)
    else:
        sslserver = sslclient = None
    if 'quic' in rawprotos or 'h3' in protonames:
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
    if 'h2' in rawprotos:
        try:
            import h2
        except ImportError:
            raise ConfigurationError('Missing library: "pip3 install h2"') from None
    urlpath, _, plugins = url.path.partition(',')
    urlpath, _, lbind = urlpath.partition('@')
    plugins = plugins.split(',') if plugins else None
    cipher, _, loc = url.netloc.rpartition('@')
    if cipher:
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
        if plugins:
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
    if url.fragment.startswith('#'):
        with open(url.fragment[1:]) as auth_file:
            auth = auth_file.read().rstrip().encode()
    else:
        auth = url.fragment.encode()
    users = [item.rstrip() for item in auth.split(b'\n')] if auth else None
    if 'httpadmin' in protonames and not users:
        raise argparse.ArgumentTypeError('httpadmin requires credentials in the URI fragment')
    if 'direct' in protonames:
        return ProxyDirect(lbind=lbind)

    params = ProxyConfig(
        jump=jump,
        protos=protos,
        cipher=cipher,
        users=users,
        rule=url.query,
        bind=loc or urlpath,
        host_name=host_name,
        port=port,
        unix=not loc,
        lbind=lbind,
        sslclient=sslclient,
        sslserver=sslserver,
        insecure_host_key='insecure' in rawprotos and 'ssh' in rawprotos,
    ).as_kwargs()
    if 'quic' in rawprotos:
        from ..quic import ProxyQUIC

        proxy = ProxyQUIC(quicserver, quicclient, **params)
    elif 'h3' in protonames:
        from ..quic import ProxyH3

        proxy = ProxyH3(quicserver, quicclient, **params)
    elif 'h2' in protonames:
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
