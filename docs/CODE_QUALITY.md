# Code Quality Policy

This project keeps code-quality checks useful without making a style-only change a
runtime compatibility risk.

## Gates and reports

Ruff gates syntax and undefined-name errors (`E9,F821`). Pylint gates the selected
correctness messages `E0102` and `W0640`. The remaining Pylint messages are
informational reports and are reviewed when code in the affected area changes.

The project does not currently make the complete Pylint report a merge gate. A
complete gate would need a baseline and a staged adoption plan so that legacy
protocol implementations and optional backends are not changed only to satisfy a
convention threshold.

## Line length

New and maintainable code follows the 100-character Ruff limit. A small number of
legacy modules contain serialized wire-format records, cryptographic round tables,
or generated compatibility constants. Those values are kept together to make their
relationship to the protocol or algorithm visible; their module-level Pylint
suppression is intentional.

## Runtime state and complexity

`ProxyDirect` owns listener, UDP association, and task lifecycle state. `ProxySimple`
extends it with the fields parsed from a proxy URI. Splitting either object into
additional state holders would add indirection to connection setup and could break
callers that inspect existing attributes. The Pylint attribute-count findings are
therefore documented exceptions, not a reason for a speculative refactor.

HTTP/2 and other multiplexed handlers keep their connection state in one event-loop
scope. Their local-variable and branch-count findings are reviewed together with
flow-control and shutdown changes.

## Tests and benchmarks

Test method names describe the behavior under test, so a second one-line docstring
is not required for every test method. Benchmark entry points and reusable benchmark
helpers do have docstrings. Small fake readers, writers, and protocol objects are
purpose-built fixtures; their low public-method count and limited duplication are
not production design problems.

Benchmark scripts may bootstrap the repository root on `sys.path` so they can be
run directly from a source checkout. The corresponding import-position exception
is explicit and does not affect the installed package.

## Imports and cycles

Optional dependencies remain lazy so importing the core package does not require an
optional backend. Server handlers are also imported locally where necessary to keep
the compatibility facade and concrete server modules acyclic at runtime. A lazy
import should be removed only when the dependency is unconditional and the import
graph has been checked.

## Review rule

Prefer a small, behavior-preserving cleanup when the warning identifies a real
maintenance problem. Keep a documented, narrow exception when fixing the warning
would obscure a protocol invariant, duplicate state, alter callback compatibility,
or introduce a measurable hot-path cost. Reconsider the full Pylint gate after the
remaining legacy modules or test fixtures receive a dedicated maintenance pass.
