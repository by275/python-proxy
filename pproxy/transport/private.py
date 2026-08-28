"""Small compatibility boundary for third-party and asyncio private APIs."""

# These helpers intentionally centralize version-sensitive private access.
# pylint: disable=protected-access


def h2_begin_stream(connection, stream_id, weight):
    """Begin an outbound H2 stream through the version-sensitive API."""
    return connection._begin_new_stream(stream_id, weight)


def quic_protocol(writer):
    """Return the aioquic protocol associated with an adapted writer."""
    return writer._transport.protocol


def quic_network_address(connection):
    """Return the active network path address from an aioquic connection."""
    return connection._quic._network_paths[0].addr


def quic_connection(protocol):
    """Return the low-level QUIC connection for H3 construction."""
    return protocol._quic


def quic_next_stream_id(connection, is_unidirectional=False):
    """Allocate an aioquic stream id through one compatibility hook."""
    return connection._quic.get_next_available_stream_id(is_unidirectional)


def quic_prepare_stream(connection, stream_id):
    """Create the internal aioquic stream state before sending data."""
    return connection._quic._get_or_create_stream_for_send(stream_id)


def quic_create_stream(connection, stream_id):
    """Create an aioquic reader/writer pair through the compatibility boundary."""
    return connection._create_stream(stream_id)


def quic_send_stream_data(connection, stream_id, data, end_stream=False):
    """Send stream data through the aioquic compatibility boundary."""
    return connection._quic.send_stream_data(stream_id, data, end_stream)


def quic_is_closed(protocol):
    """Return whether an aioquic protocol has completed its close event."""
    return protocol._closed.is_set()


def quic_force_closed(protocol):
    """Mark an aioquic protocol closed after cancelling an unfinished handshake."""
    protocol._closed.set()
