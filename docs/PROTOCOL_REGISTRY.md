# Protocol Registry Metadata

`pproxy.proto.PROTOCOL_METADATA` provides additive capability information for the
schemes in the existing protocol registry. The legacy `MAPPINGS` dictionary and URI
resolution behavior remain unchanged.

Each value is a `ProtocolMetadata` record with these fields:

- `supports_tcp`: the scheme can carry a TCP stream;
- `supports_udp`: the scheme can carry UDP datagrams;
- `supports_client`: the scheme can be used for an outbound connection;
- `supports_server`: the scheme can accept an inbound proxy connection;
- `optional_dependency`: package name required for an optional backend, if any;
- `default_port`: the default URI port used by the proxy configuration, if applicable;
- `transport_modifier`: the scheme modifies transport setup rather than identifying a
  standalone protocol.

Applications can query metadata without changing protocol selection:

```python
from pproxy import proto

metadata = proto.get_protocol_metadata("socks5")
if metadata and metadata.supports_udp:
    print("SOCKS5 UDP is available")
```

An optional adapter may publish its own metadata while retaining the original two-
argument registration form:

```python
metadata = proto.ProtocolMetadata(
    supports_tcp=True,
    supports_udp=False,
    supports_client=True,
    supports_server=True,
    optional_dependency="adapter-package",
    default_port=8080,
)
proto.register_protocol("adapter", Adapter, metadata)
```

The metadata is descriptive. It does not install dependencies, alter URI parsing, or
make an optional backend available by itself.

The lifecycle and dependency contract for optional transports is documented in
[`OPTIONAL_ADAPTERS.md`](OPTIONAL_ADAPTERS.md). The CLI supported-protocol line is
derived from this registry's non-modifier metadata entries, so help output and
capability metadata stay aligned when a registered protocol is added.
