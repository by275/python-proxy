# Changelog

## Unreleased

This modernization keeps the existing CLI, URI grammar, public factory names,
and protocol wire formats compatible for Python 3.12+ Git installations.

### Internal improvements

- Split protocol parsing and implementations into `pproxy.protocols` while
  keeping the `pproxy.proto` compatibility facade.
- Added a protocol registry extension hook for future optional adapters such
  as `cfp://`; CFP is not enabled by this branch.
- Added `pproxy.runtime.TaskRegistry` and additive `wait_closed()`, `aclose()`,
  and async context-manager support to runtime proxy objects. Existing
  synchronous `close()` and `start_server(args)` calls remain valid.
- Added opt-in JSON logging through `pproxy.observability`; legacy verbose
  output is unchanged unless an application configures the new logger.
- Preserved the existing optional dependency boundaries for H2, H3, QUIC,
  SSH, accelerated ciphers, and daemon mode.
- Added a documented lifecycle contract and capability metadata for optional
  adapters, plus dependency-range synchronization checks.
- Removed optional adapter imports from the server facade dependency cycle while
  retaining the historical server aliases.
- Added lifecycle-aware Client/Server examples and documented the independent
  relationship between structured logging and legacy verbose output.
- Generated the CLI supported-protocol list from registry metadata and aligned
  Git installation, optional extras, Python requirements, and container usage
  documentation.
- Fixed HTTP/2 multiplexed stream writers not waking for connection-level flow
  control updates after the shared send window was exhausted.
- Added an encrypted plugin path to the loopback benchmark and recorded the
  Phase 4 workload review without accepting unmeasured hot-path rewrites.
- Documented the legacy-cipher warning policy, AEAD recommendation, and the
  review gates required before any compatibility removal.

### Verification

- Core unittest contracts pass under normal and optimized (`python -O`)
  interpreters.
- Clean wheel builds include all protocol, transport, and runtime subpackages.
- Dockerfile, `entrypoint.sh`, and `dev.txt` are intentionally outside this
  modernization and are not part of the release commits.
