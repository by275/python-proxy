# Security and Compatibility Policy

This policy keeps the existing protocol and cipher wire formats usable while
making safer choices clear for new deployments. It applies to the current
Python 3.12+ Git installation and does not remove any existing cipher name.

## Cipher categories

The following ciphers are retained for wire compatibility only:

- RC4 (`rc4`)
- RC4-MD5 (`rc4-md5`)
- Blowfish-CFB (`bf-cfb`)
- CAST5-CFB (`cast5-cfb`)
- DES-CFB (`des-cfb`)

New deployments should prefer an authenticated-encryption cipher such as
`chacha20-ietf-poly1305` or `aes-256-gcm`. Other non-AEAD ciphers remain
available when an existing peer requires them. The pure-Python implementations
are compatibility fallbacks for environments without PyCryptodome; selecting
the fallback does not change the cipher name or wire format.

## Current warning behavior

Selecting a legacy cipher emits a `UserWarning` from `get_cipher()` while still
returning a usable cipher factory. The warning is intentionally non-blocking:
existing peers can continue to communicate, and applications can use their
normal warnings filters while migrating. No packet boundary, nonce/IV, tag,
plugin framing, or protocol selection is changed by this policy.

The warning is covered for every legacy cipher, while recommended AEAD ciphers
are covered by a no-warning regression test. No opt-in enforcement or runtime
rejection is enabled in this branch.

## Deprecation and removal gates

There is no scheduled removal release for legacy ciphers. A future change may
consider deprecation or removal only after all of the following have been
reviewed:

1. Real configuration and peer usage has been inventoried, including scripted
   and long-lived deployments.
2. A compatible replacement has been verified against the affected peers and
   documented with a migration example.
3. The warning volume, support burden, and security benefit justify the change.
4. The change is announced before enforcement, with a clearly identified
   release boundary and an opt-out or compatibility window where appropriate.
5. A separate compatibility review approves the affected CLI, URI, cipher,
   plugin, and wire-format surfaces.

Removing a cipher from the registry, changing its default, or changing the
warning class is therefore not an automatic follow-up to this policy. It
requires explicit approval after the evidence above is available.

## Rollback

If a deprecation or enforcement change causes interoperability failures, the
rollback is to restore the previous registry entry and warning policy in a
revert commit. The legacy implementation, test vectors, and peer-compatible
framing must remain recoverable until the removal review is complete. Rollback
must not silently alter packet boundaries, nonce/IV handling, authentication,
or plugin framing.

## Callback and API compatibility

Protocol callbacks retain their established positional signatures and common
keyword context. Existing `**kw` parameters are compatibility points because
the dispatcher supplies shared context to different protocol implementations.
Changing callbacks to keyword-only context, removing unused compatibility
arguments, or changing warning behavior in a way that breaks filters requires
the same explicit review and migration process. The current branch makes no
such API change.
