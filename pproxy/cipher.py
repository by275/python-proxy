"""Cipher factories and stream/datagram cipher adapters."""

# Accelerated and pure-Python cipher maps are loaded lazily to keep the core
# installation independent of optional crypto packages.
# pylint: disable=import-outside-toplevel
# Cipher class names intentionally mirror protocol algorithm names.
# pylint: disable=invalid-name

import copy
import os
import hashlib
import hmac
import warnings
from typing import Any, Callable, ClassVar

from . import transport
from .errors import ProtocolError, require

LEGACY_CIPHERS = frozenset({'rc4', 'rc4-md5', 'bf-cfb', 'cast5-cfb', 'des-cfb'})

class BaseCipher:
    """Common state and backend hooks for stream and packet ciphers."""

    PYTHON: ClassVar[bool] = False
    CACHE: ClassVar[dict[bytes, bytes]] = {}
    KEY_LENGTH: ClassVar[int] = 0
    IV_LENGTH: ClassVar[int] = 0
    cipher: Any
    key: bytes
    ota: bool
    iv: bytes | None
    stream_buffer: bytes

    def setup(self):
        """Initialize the backend cipher after the IV has been selected."""
        raise NotImplementedError

    def __init__(self, key, ota=False, setup_key=True):
        """Create a cipher session and derive its connection key if needed."""
        if self.KEY_LENGTH > 0 and setup_key:
            self.key = self.CACHE.get(b'key'+key)
            if self.key is None:
                keybuf = []
                while len(b''.join(keybuf)) < self.KEY_LENGTH:
                    keybuf.append(hashlib.md5((keybuf[-1] if keybuf else b'') + key).digest())
                self.key = self.CACHE[b'key'+key] = b''.join(keybuf)[:self.KEY_LENGTH]
        else:
            self.key = key
        self.ota = ota
        self.iv = None
        self.stream_buffer = b''
    def setup_iv(self, iv=None):
        """Select an IV and initialize the backend cipher."""
        self.iv = os.urandom(self.IV_LENGTH) if iv is None else iv
        self.setup()
        return self
    def decrypt(self, s):
        """Decrypt one byte string with the initialized backend."""
        return self.cipher.decrypt(s)

    def encrypt(self, s):
        """Encrypt one byte string with the initialized backend."""
        return self.cipher.encrypt(s)

    @classmethod
    def name(cls):
        """Return the protocol-facing name of a cipher class."""
        return cls.__name__.replace('_Cipher', '').replace('_', '-').lower()

class AEADCipher(BaseCipher):
    """Base adapter for packetized authenticated-encryption ciphers."""

    PACKET_LIMIT = 16*1024-1
    NONCE_LENGTH: ClassVar[int] = 0
    TAG_LENGTH: ClassVar[int] = 0
    cipher_new: Callable[..., Any]
    _nonce: int
    _buffer: bytearray
    _declen: int | None

    def decrypt_and_verify(self, buffer, tag):
        """Decrypt one authenticated packet using the backend primitive."""
        raise NotImplementedError

    def encrypt_and_digest(self, buffer):
        """Encrypt one packet and return its authentication tag."""
        raise NotImplementedError

    def setup_iv(self, iv=None):
        """Derive packet keys and reset authenticated stream state."""
        self.iv = os.urandom(self.IV_LENGTH) if iv is None else iv
        randkey = hmac.new(self.iv, self.key, hashlib.sha1).digest()
        blocks_needed = (self.KEY_LENGTH + len(randkey) - 1) // len(randkey)
        okm = bytearray()
        output_block = b''
        for counter in range(blocks_needed):
            output_block = hmac.new(randkey, output_block + b'ss-subkey' + bytes([counter+1]), hashlib.sha1).digest()
            okm.extend(output_block)
        self.key = bytes(okm[:self.KEY_LENGTH])
        self._nonce = 0
        self._buffer = bytearray()
        self._declen = None
        self.setup()
        return self
    @property
    def nonce(self):
        """Return the next packet nonce and advance the packet counter."""
        ret = self._nonce.to_bytes(self.NONCE_LENGTH, 'little')
        self._nonce = (self._nonce+1) & ((1<<self.NONCE_LENGTH)-1)
        return ret
    def decrypt(self, s):
        """Buffer and decrypt complete authenticated packets."""
        self._buffer.extend(s)
        ret = bytearray()
        try:
            while 1:
                if self._declen is None:
                    if len(self._buffer) < 2+self.TAG_LENGTH:
                        break
                    self._declen = int.from_bytes(self.decrypt_and_verify(self._buffer[:2], self._buffer[2:2+self.TAG_LENGTH]), 'big')
                    require(self._declen <= self.PACKET_LIMIT)
                    del self._buffer[:2+self.TAG_LENGTH]
                else:
                    if len(self._buffer) < self._declen+self.TAG_LENGTH:
                        break
                    ret.extend(self.decrypt_and_verify(self._buffer[:self._declen], self._buffer[self._declen:self._declen+self.TAG_LENGTH]))
                    del self._buffer[:self._declen+self.TAG_LENGTH]
                    self._declen = None
        # Crypto backends expose different exception classes; any failure must
        # discard the packet state and fail closed.
        except Exception as exc:
            self._buffer.clear()
            self._declen = None
            raise ProtocolError('invalid AEAD packet') from exc
        return bytes(ret)
    def encrypt(self, s):
        """Split data into authenticated packets and encrypt them."""
        ret = bytearray()
        for i in range(0, len(s), self.PACKET_LIMIT):
            buf = s[i:i+self.PACKET_LIMIT]
            len_chunk, len_tag = self.encrypt_and_digest(len(buf).to_bytes(2, 'big'))
            body_chunk, body_tag = self.encrypt_and_digest(buf)
            ret.extend(len_chunk+len_tag+body_chunk+body_tag)
        return bytes(ret)

class RC4_Cipher(BaseCipher):
    """PyCryptodome RC4 stream cipher adapter."""

    KEY_LENGTH = 16
    IV_LENGTH = 0
    def setup(self):
        from Crypto.Cipher import ARC4
        self.cipher = ARC4.new(self.key)

class RC4_MD5_Cipher(RC4_Cipher):
    """RC4 adapter with the legacy MD5-derived session key."""

    IV_LENGTH = 16
    def setup(self):
        self.key = hashlib.md5(self.key + self.iv).digest()
        RC4_Cipher.setup(self)

class ChaCha20_Cipher(BaseCipher):
    """PyCryptodome ChaCha20 stream cipher adapter."""

    KEY_LENGTH = 32
    IV_LENGTH = 8
    def setup(self):
        from Crypto.Cipher import ChaCha20
        self.cipher = ChaCha20.new(key=self.key, nonce=self.iv)
class ChaCha20_IETF_Cipher(ChaCha20_Cipher):
    """ChaCha20 adapter using the IETF nonce size."""

    IV_LENGTH = 12

class Salsa20_Cipher(BaseCipher):
    """PyCryptodome Salsa20 stream cipher adapter."""

    KEY_LENGTH = 32
    IV_LENGTH = 8
    def setup(self):
        from Crypto.Cipher import Salsa20
        self.cipher = Salsa20.new(key=self.key, nonce=self.iv)

class AES_256_CFB_Cipher(BaseCipher):
    """AES-256 CFB stream cipher adapter."""

    KEY_LENGTH = 32
    IV_LENGTH = 16
    SEGMENT_SIZE = 128
    def setup(self):
        from Crypto.Cipher import AES
        self.cipher = AES.new(self.key, AES.MODE_CFB, iv=self.iv, segment_size=self.SEGMENT_SIZE)
class AES_128_CFB_Cipher(AES_256_CFB_Cipher):
    """AES-128 CFB stream cipher variant."""

    KEY_LENGTH = 16
class AES_192_CFB_Cipher(AES_256_CFB_Cipher):
    """AES-192 CFB stream cipher variant."""

    KEY_LENGTH = 24

class AES_256_CFB8_Cipher(AES_256_CFB_Cipher):
    """AES-256 CFB8 stream cipher variant."""

    SEGMENT_SIZE = 8
class AES_192_CFB8_Cipher(AES_256_CFB8_Cipher):
    """AES-192 CFB8 stream cipher variant."""

    KEY_LENGTH = 24
class AES_128_CFB8_Cipher(AES_256_CFB8_Cipher):
    """AES-128 CFB8 stream cipher variant."""

    KEY_LENGTH = 16

class AES_256_OFB_Cipher(BaseCipher):
    """AES-256 OFB stream cipher adapter."""

    KEY_LENGTH = 32
    IV_LENGTH = 16
    def setup(self):
        from Crypto.Cipher import AES
        self.cipher = AES.new(self.key, AES.MODE_OFB, iv=self.iv)
class AES_192_OFB_Cipher(AES_256_OFB_Cipher):
    """AES-192 OFB stream cipher variant."""

    KEY_LENGTH = 24
class AES_128_OFB_Cipher(AES_256_OFB_Cipher):
    """AES-128 OFB stream cipher variant."""

    KEY_LENGTH = 16

class AES_256_CTR_Cipher(BaseCipher):
    """AES-256 CTR stream cipher adapter."""

    KEY_LENGTH = 32
    IV_LENGTH = 16
    def setup(self):
        from Crypto.Cipher import AES
        self.cipher = AES.new(self.key, AES.MODE_CTR, nonce=b'', initial_value=self.iv)
class AES_192_CTR_Cipher(AES_256_CTR_Cipher):
    """AES-192 CTR stream cipher variant."""

    KEY_LENGTH = 24
class AES_128_CTR_Cipher(AES_256_CTR_Cipher):
    """AES-128 CTR stream cipher variant."""

    KEY_LENGTH = 16

class AES_256_GCM_Cipher(AEADCipher):
    """AES-256 GCM authenticated-encryption adapter."""

    KEY_LENGTH = 32
    IV_LENGTH = 32
    NONCE_LENGTH = 12
    TAG_LENGTH = 16
    def decrypt_and_verify(self, buffer, tag):
        """Decrypt and authenticate one AES-GCM packet."""
        return self.cipher_new(self.nonce).decrypt_and_verify(buffer, tag)
    def encrypt_and_digest(self, buffer):
        """Encrypt one AES-GCM packet and return its tag."""
        return self.cipher_new(self.nonce).encrypt_and_digest(buffer)
    def setup(self):
        from Crypto.Cipher import AES
        self.cipher_new = lambda nonce: AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=self.TAG_LENGTH)
class AES_192_GCM_Cipher(AES_256_GCM_Cipher):
    """AES-192 GCM authenticated-encryption variant."""

    KEY_LENGTH = IV_LENGTH = 24
class AES_128_GCM_Cipher(AES_256_GCM_Cipher):
    """AES-128 GCM authenticated-encryption variant."""

    KEY_LENGTH = IV_LENGTH = 16

class ChaCha20_IETF_POLY1305_Cipher(AEADCipher):
    """ChaCha20-Poly1305 authenticated-encryption adapter."""

    KEY_LENGTH = 32
    IV_LENGTH = 32
    NONCE_LENGTH = 12
    TAG_LENGTH = 16
    def decrypt_and_verify(self, buffer, tag):
        """Decrypt and authenticate one ChaCha20-Poly1305 packet."""
        return self.cipher_new(self.nonce).decrypt_and_verify(buffer, tag)
    def encrypt_and_digest(self, buffer):
        """Encrypt one ChaCha20-Poly1305 packet and return its tag."""
        return self.cipher_new(self.nonce).encrypt_and_digest(buffer)
    def setup(self):
        from Crypto.Cipher import ChaCha20_Poly1305
        self.cipher_new = lambda nonce: ChaCha20_Poly1305.new(key=self.key, nonce=nonce)

class BF_CFB_Cipher(BaseCipher):
    """Legacy Blowfish CFB cipher adapter."""

    KEY_LENGTH = 16
    IV_LENGTH = 8
    def setup(self):
        from Crypto.Cipher import Blowfish
        self.cipher = Blowfish.new(self.key, Blowfish.MODE_CFB, iv=self.iv, segment_size=64)

class CAST5_CFB_Cipher(BaseCipher):
    """Legacy CAST5 CFB cipher adapter."""

    KEY_LENGTH = 16
    IV_LENGTH = 8
    def setup(self):
        from Crypto.Cipher import CAST
        self.cipher = CAST.new(self.key, CAST.MODE_CFB, iv=self.iv, segment_size=64)

class DES_CFB_Cipher(BaseCipher):
    """Legacy DES CFB cipher adapter."""

    KEY_LENGTH = 8
    IV_LENGTH = 8
    def setup(self):
        from Crypto.Cipher import DES
        self.cipher = DES.new(self.key, DES.MODE_CFB, iv=self.iv, segment_size=64)

class PacketCipher:
    """Create independent packet cipher sessions for datagram payloads."""

    def __init__(self, cipher, key, name):
        """Store the cipher factory and its wire-facing metadata."""
        self.cipher = lambda iv=None: cipher(key).setup_iv(iv)
        self.ivlen = cipher.IV_LENGTH
        self.name = name
    def decrypt(self, data):
        """Decrypt a packet containing its prepended IV."""
        return self.cipher(data[:self.ivlen]).decrypt(data[self.ivlen:])

    def encrypt(self, data):
        """Encrypt a packet and prepend its newly generated IV."""
        cipher = self.cipher()
        return cipher.iv+cipher.encrypt(data)


class StreamCipherAdapter:  # pylint: disable=too-many-instance-attributes
    """Attach a stream cipher and its plugin chain to asyncio streams."""

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, cipher, key, reader, writer, pdecrypt, pdecrypt2, pencrypt, pencrypt2, ota=False
    ):
        """Create a stream adapter around reader and writer callbacks."""
        self.reader = reader
        self.writer = writer
        self.pdecrypt = pdecrypt
        self.pdecrypt2 = pdecrypt2
        self.pencrypt = pencrypt
        self.pencrypt2 = pencrypt2
        self.reader_cipher = cipher(key, ota=ota)
        self.writer_cipher = cipher(key, ota=ota)
        self._raw_read = reader.feed_data
        self._raw_write = writer.write

    def decrypt(self, data):
        """Decrypt inbound bytes after applying the plugin chain."""
        data = self.pdecrypt2(data)
        if not self.reader_cipher.iv:
            data = self.reader_cipher.stream_buffer + data
            if len(data) >= self.reader_cipher.IV_LENGTH:
                self.reader_cipher.setup_iv(data[:self.reader_cipher.IV_LENGTH])
                return self.pdecrypt(self.reader_cipher.decrypt(data[self.reader_cipher.IV_LENGTH:]))
            self.reader_cipher.stream_buffer = data
            return b''
        return self.pdecrypt(self.reader_cipher.decrypt(data))

    def feed_data(self, data):
        """Process decrypted reader data and feed the raw reader callback."""
        try:
            for decrypt in self.reader.decrypts:
                data = decrypt(data)
                if not data:
                    return
        except ProtocolError:
            close = getattr(self.writer, 'close', None)
            if close is not None:
                close()
            raise
        self._raw_read(data)

    def write(self, data):
        """Encrypt outbound bytes and write them to the raw writer."""
        if not self.writer_cipher.iv:
            self.writer_cipher.setup_iv()
            self._raw_write(self.pencrypt2(self.writer_cipher.iv))
        if not data:
            return None
        return self._raw_write(self.pencrypt2(self.writer_cipher.encrypt(self.pencrypt(data))))

    def attach(self):
        """Install adapter callbacks and return both cipher sessions."""
        if hasattr(self.reader, 'decrypts'):
            self.reader.decrypts.append(self.decrypt)
        else:
            self.reader.decrypts = [self.decrypt]
            self.reader.feed_data = self.feed_data
            buffered = transport.take_buffer(self.reader)
            if buffered:
                self.feed_data(buffered)
        self.writer.write = self.write
        return self.reader_cipher, self.writer_cipher

class CipherFactory:
    """Immutable cipher configuration that creates connection-local sessions."""

    def __init__(self, cipher, key, name, ota=False, plugins=None):
        self.cipher = cipher
        self.key = key
        self.name = name
        self.ota = ota
        self.legacy = name.removesuffix('-py') in LEGACY_CIPHERS
        self.plugins = list(plugins or ())
        self.datagram = PacketCipher(cipher, key, name)

    def __call__(self, reader, writer, pdecrypt, pdecrypt2, pencrypt, pencrypt2):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        """Attach connection-local stream cipher state to asyncio streams."""
        return StreamCipherAdapter(
            self.cipher,
            self.key,
            reader,
            writer,
            pdecrypt,
            pdecrypt2,
            pencrypt,
            pencrypt2,
            self.ota,
        ).attach()

    def for_connection(self):
        """Return a session whose plugin state belongs to one connection."""
        return CipherFactory(
            self.cipher,
            self.key,
            self.name,
            self.ota,
            (copy.deepcopy(plugin) for plugin in self.plugins),
        )


MAP = {cls.name(): cls for name, cls in globals().items() if name.endswith('_Cipher')}

def get_cipher(cipher_key):
    """Resolve a configured cipher string to a connection-local factory."""
    from .cipherpy import MAP as MAP_PY
    cipher, key = cipher_key.split(':')
    cipher_name, ota, _ = cipher.partition('!')
    if cipher_name not in MAP and cipher_name not in MAP_PY and not (cipher_name.endswith('-py') and cipher_name[:-3] in MAP_PY):
        return f'existing ciphers: {sorted(set(MAP)|set(MAP_PY))}', None
    key, ota = key.encode(), bool(ota) if ota else False
    cipher = MAP.get(cipher_name)
    if cipher:
        try:
            if __import__('Crypto').version_info < (3, 4):
                cipher = None
        except ImportError:
            cipher = None
    if cipher is None:
        cipher = MAP_PY.get(cipher_name)
        if cipher is None and cipher_name.endswith('-py'):
            cipher_name = cipher_name[:-3]
            cipher = MAP_PY.get(cipher_name)
    if cipher is None:
        return 'this cipher needs library: "pip3 install pycryptodome"', None
    cipher_name += ('-py' if cipher.PYTHON else '')
    if cipher_name.removesuffix('-py') in LEGACY_CIPHERS:
        warnings.warn(
            f'legacy cipher {cipher_name!r} is retained for compatibility; prefer an AEAD cipher',
            UserWarning,
            stacklevel=2,
        )
    return None, CipherFactory(cipher, key, cipher_name, ota)
