"""TCP and UDP request handlers for configured proxy listeners."""

import asyncio

from .. import proto
from ..errors import (
    BlockedConnection,
    ConnectionClosed,
    ProtocolError,
    UpstreamError,
)
from .common import AuthTable, DUMMY, prepare_ciphers, schedule
from .connections import DIRECT


async def stream_handler(
    reader,
    writer,
    unix,
    lbind,
    protos,
    rserver,
    cipher,
    sslserver,
    debug=0,
    authtime=86400 * 30,
    block=None,
    salgorithm='fa',
    verbose=DUMMY,
    modstat=lambda user, remote, host: lambda index: DUMMY,
    task_registry=None,
    **kwargs,
):
    """Accept one client stream and relay it through the selected upstream."""
    remote_ip = 'unknown_remote_ip'
    try:
        reader, writer = proto.sslwrap(reader, writer, sslserver, True, None, verbose, task_registry)
        if unix:
            remote_ip, server_ip, remote_text = 'local', None, 'unix_local'
        else:
            peername = writer.get_extra_info('peername')
            remote_ip, remote_port, *_ = peername if peername else ('unknow_remote_ip', 'unknow_remote_port')
            server_ip = writer.get_extra_info('sockname')[0]
            remote_text = f'{remote_ip}:{remote_port}'
        local_addr = None if server_ip in ('127.0.0.1', '::1', None) else (server_ip, 0)
        reader_cipher, _ = await prepare_ciphers(cipher, reader, writer, server_side=False)
        lproto, user, host_name, port, client_connected = await proto.accept(
            protos,
            reader=reader,
            writer=writer,
            authtable=AuthTable(remote_ip, authtime),
            reader_cipher=reader_cipher,
            sock=writer.get_extra_info('socket'),
            **kwargs,
        )
        if host_name == 'echo':
            await lproto.channel(reader, writer, DUMMY, DUMMY)
        elif host_name == 'empty':
            await lproto.channel(reader, writer, None, DUMMY)
        elif block and block(host_name):
            raise BlockedConnection('BLOCK ' + host_name)
        else:
            roption = schedule(rserver, salgorithm, host_name, port) or DIRECT
            verbose(f'{lproto.name} {remote_text}{roption.logtext(host_name, port)}')
            try:
                reader_remote, writer_remote = await roption.open_connection(host_name, port, local_addr, lbind)
            except asyncio.TimeoutError as exc:
                raise UpstreamError(f'Connection timeout {roption.bind}') from exc
            try:
                reader_remote, writer_remote = await roption.prepare_connection(
                    reader_remote, writer_remote, host_name, port
                )
                use_http = (await client_connected(writer_remote)) if client_connected else None
            except (ConnectionError, OSError, EOFError, asyncio.TimeoutError, ValueError, ProtocolError) as exc:
                writer_remote.close()
                raise UpstreamError('Unknown remote protocol') from exc
            m = modstat(user, remote_ip, host_name)
            lchannel = lproto.http_channel if use_http else lproto.channel
            from ..relay import relay_with_taskgroup

            await relay_with_taskgroup(
                lproto.channel(reader_remote, writer, m(2 + roption.direct), m(4 + roption.direct)),
                lchannel(reader, writer_remote, m(roption.direct), roption.connection_change),
            )
    except asyncio.CancelledError:
        raise
    except (ConnectionClosed, ProtocolError, ConnectionError, OSError, EOFError, asyncio.TimeoutError, ValueError) as ex:
        if not isinstance(ex, ConnectionClosed):
            verbose(f'{str(ex) or "Unsupported protocol"} from {remote_ip}')
        if debug:
            raise
    # Keep the service boundary alive for backend-specific unexpected errors.
    except Exception as ex:
        verbose(f'Unhandled proxy error {type(ex).__name__}: {ex} from {remote_ip}')
        if debug:
            raise
    finally:
        try:
            writer.close()
        except (AttributeError, OSError):
            pass


async def datagram_handler(
    writer,
    data,
    addr,
    protos,
    urserver,
    block,
    cipher,
    salgorithm,
    verbose=DUMMY,
    **kwargs,
):
    """Handle one UDP datagram under the same policy as stream requests."""
    remote_ip = 'unknown_remote_ip'
    try:
        remote_ip, remote_port, *_ = addr
        remote_text = f'{remote_ip}:{remote_port}'
        data = cipher.datagram.decrypt(data) if cipher else data
        lproto, user, host_name, port, data = proto.udp_accept(
            protos, data, sock=writer.get_extra_info('socket'), **kwargs
        )
        if host_name == 'echo':
            writer.sendto(data, addr)
        elif host_name == 'empty':
            pass
        elif block and block(host_name):
            raise BlockedConnection('BLOCK ' + host_name)
        else:
            roption = schedule(urserver, salgorithm, host_name, port) or DIRECT
            verbose(f'UDP {lproto.name} {remote_text}{roption.logtext(host_name, port)}')
            data = roption.udp_prepare_connection(host_name, port, data)

            def reply(rdata):
                rdata = lproto.udp_pack(host_name, port, rdata)
                writer.sendto(cipher.datagram.encrypt(rdata) if cipher else rdata, addr)

            await roption.udp_open_connection(host_name, port, data, addr, reply)
    except asyncio.CancelledError:
        raise
    except (ConnectionClosed, ProtocolError, ConnectionError, OSError, EOFError, asyncio.TimeoutError, ValueError) as ex:
        if not isinstance(ex, ConnectionClosed):
            verbose(f'{str(ex) or "Unsupported protocol"} from {remote_ip}')
    # Keep the datagram service alive for backend-specific unexpected errors.
    except Exception as ex:
        verbose(f'Unhandled proxy error {type(ex).__name__}: {ex} from {remote_ip}')
