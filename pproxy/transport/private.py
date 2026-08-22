"""Small compatibility boundary for third-party and asyncio private APIs."""


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


def quic_send_stream_data(connection, stream_id, data, end_stream=False):
    """Send stream data through the aioquic compatibility boundary."""
    return connection._quic.send_stream_data(stream_id, data, end_stream)
