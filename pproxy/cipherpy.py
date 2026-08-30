"""Pure-Python cipher implementations retained for compatibility."""

import base64
import hashlib
import struct
from typing import Any, Callable, ClassVar, Iterator

from .cipher import BaseCipher, AEADCipher
from .errors import require

# Names and constants mirror the algorithms and the existing cipher registry.
# This compatibility backend contains serialized constants and compact rounds.
# pylint: disable=invalid-name,line-too-long

class Table_Cipher(BaseCipher):
    """Table-based substitution cipher used by the legacy protocol."""

    PYTHON = True
    KEY_LENGTH = 0
    IV_LENGTH = 0
    encrypt_table: bytes
    decrypt_table: bytes
    def setup(self):
        if self.key in self.CACHE:
            self.encrypt_table, self.decrypt_table = self.CACHE[self.key]
        else:
            a, _ = struct.unpack('<QQ', hashlib.md5(self.key).digest())
            table = list(range(256))
            for i in range(1, 1024):
                table.sort(key = lambda x, i=i: a % (x + i))
            self.encrypt_table = bytes(table)
            self.decrypt_table = bytes.maketrans(self.encrypt_table, bytes(range(256)))
            self.CACHE[self.key] = self.encrypt_table, self.decrypt_table
    def decrypt(self, s):
        return bytes.translate(s, self.decrypt_table)
    def encrypt(self, s):
        return bytes.translate(s, self.encrypt_table)

class StreamCipher(BaseCipher):
    """Base class for pure-Python byte-oriented stream ciphers."""

    PYTHON = True
    stream: Iterator[int]

    def core(self):
        """Return the keystream iterator implemented by each stream cipher."""
        raise NotImplementedError

    def setup(self):
        self.stream = self.core()
    def encrypt(self, s):
        ret = bytearray()
        for i in s:
            ret.append(i^next(self.stream))
        return bytes(ret)
        #return bytes(i^next(self.stream) for i in s)
    decrypt = encrypt

class RC4_Cipher(StreamCipher):
    """Pure-Python RC4 stream cipher implementation."""

    KEY_LENGTH = 16
    IV_LENGTH = 0
    def core(self):
        data = list(range(256))
        y = 0
        for x in range(256):
            y = self.key[x%self.KEY_LENGTH]+data[x]+y & 0xff
            data[x], data[y] = data[y], data[x]
        x = y = 0
        while 1:
            x = x+1 & 0xff
            y = y+data[x] & 0xff
            data[x], data[y] = data[y], data[x]
            yield data[data[x]+data[y] & 0xff]

class RC4_MD5_Cipher(RC4_Cipher):
    """RC4 variant with a legacy MD5-derived session key."""

    IV_LENGTH = 16
    def setup(self):
        self.key = hashlib.md5(self.key + self.iv).digest()
        RC4_Cipher.setup(self)

ORDERS_CHACHA20 = ((0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)) * 10
ORDERS_SALSA20 = ((4,0,12,8),(9,5,1,13),(14,10,6,2),(3,15,11,7),(1,0,3,2),(6,5,4,7),(11,10,9,8),(12,15,14,13)) * 10
def ROL(a, b):
    """Rotate a 32-bit integer left by the requested number of bits."""
    return a<<b&0xffffffff|(a&0xffffffff)>>32-b


def ChaCha20_round(H):
    """Apply the ChaCha20 quarter-round schedule to a state list."""
    for a, b, c, d in ORDERS_CHACHA20:
        H[a] += H[b]
        H[d] = ROL(H[d]^H[a], 16)
        H[c] += H[d]
        H[b] = ROL(H[b]^H[c], 12)
        H[a] += H[b]
        H[d] = ROL(H[d]^H[a], 8)
        H[c] += H[d]
        H[b] = ROL(H[b]^H[c], 7)
    return H

class ChaCha20_Cipher(StreamCipher):
    """Pure-Python ChaCha20 stream cipher implementation."""

    KEY_LENGTH = 32
    IV_LENGTH = 8
    def __init__(self, key, ota=False, setup_key=True, *, counter=0):
        super().__init__(key, ota, setup_key)
        self.counter = counter
    def core(self):
        data = list(struct.unpack('<16I', b'expand 32-byte k' + self.key + self.counter.to_bytes(4, 'little') + self.iv.rjust(12, b'\x00')))
        while 1:
            yield from struct.pack('<16I', *(a+b&0xffffffff for a, b in zip(ChaCha20_round(data[:]), data)))
            data[12:14] = (0, data[13]+1) if data[12]==0xffffffff else (data[12]+1, data[13])

class ChaCha20_IETF_Cipher(ChaCha20_Cipher):
    """ChaCha20 variant using the IETF nonce size."""

    IV_LENGTH = 12

class XChaCha20_Cipher(ChaCha20_Cipher):
    """Pure-Python XChaCha20 stream cipher implementation."""

    IV_LENGTH = 16+8
    def core(self):
        H = ChaCha20_round(list(struct.unpack('<16I', b'expand 32-byte k' + self.key + self.iv[:16])))
        key = struct.pack('<8I', *(i&0xffffffff for i in (H[:4]+H[12:])))
        data = list(struct.unpack('<16I', b'expand 32-byte k' + key + self.counter.to_bytes(4, 'little') + self.iv[16:].rjust(12, b'\x00')))
        while 1:
            yield from struct.pack('<16I', *(a+b&0xffffffff for a, b in zip(ChaCha20_round(data[:]), data)))
            data[12:14] = (0, data[13]+1) if data[12]==0xffffffff else (data[12]+1, data[13])

class XChaCha20_IETF_Cipher(XChaCha20_Cipher):
    """XChaCha20 variant using the IETF nonce size."""

    IV_LENGTH = 16+12

def poly1305(cipher_encrypt, nonce, ciphertext):
    """Compute a Poly1305 tag for ciphertext using a one-time key."""
    otk = cipher_encrypt(nonce, bytes(32))
    mac_data = ciphertext + bytes((-len(ciphertext))%16 + 8) + len(ciphertext).to_bytes(8, 'little')
    acc, r, s = 0, int.from_bytes(otk[:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff, int.from_bytes(otk[16:], 'little')
    for i in range(0, len(mac_data), 16):
        acc = (r * (acc+int.from_bytes(mac_data[i:i+16]+b'\x01', 'little'))) % ((1<<130)-5)
    return ((acc + s) & ((1<<128)-1)).to_bytes(16, 'little')

class ChaCha20_IETF_POLY1305_Cipher(AEADCipher):
    """Pure-Python ChaCha20-Poly1305 cipher implementation."""

    PYTHON = True
    KEY_LENGTH = 32
    IV_LENGTH = 32
    NONCE_LENGTH = 12
    TAG_LENGTH = 16
    cipher_encrypt: Callable[..., bytes]
    def process(self, s, tag=None):
        """Encrypt or authenticate one ChaCha20-Poly1305 packet."""
        nonce = self.nonce
        if tag is not None:
            require(tag == poly1305(self.cipher_encrypt, nonce, s))
        data = self.cipher_encrypt(nonce, s, counter=1)
        if tag is None:
            return data, poly1305(self.cipher_encrypt, nonce, data)
        return data
    encrypt_and_digest = decrypt_and_verify = process
    def setup(self):
        """Create the ChaCha20 primitive used by the Poly1305 adapter."""
        def cipher_encrypt(nonce, s, counter=0):
            """Encrypt data with a connection-local ChaCha20 session."""
            return ChaCha20_IETF_Cipher(
                self.key, setup_key=False, counter=counter
            ).setup_iv(nonce).encrypt(s)

        self.cipher_encrypt = cipher_encrypt

class XChaCha20_IETF_POLY1305_Cipher(ChaCha20_IETF_POLY1305_Cipher):
    """Pure-Python XChaCha20-Poly1305 cipher implementation."""

    NONCE_LENGTH = 16+12
    def setup(self):
        """Create the XChaCha20 primitive used by the Poly1305 adapter."""
        def cipher_encrypt(nonce, s, counter=0):
            """Encrypt data with a connection-local XChaCha20 session."""
            return XChaCha20_IETF_Cipher(
                self.key, setup_key=False, counter=counter
            ).setup_iv(nonce).encrypt(s)

        self.cipher_encrypt = cipher_encrypt

class Salsa20_Cipher(StreamCipher):
    """Pure-Python Salsa20 stream cipher implementation."""

    KEY_LENGTH = 32
    IV_LENGTH = 8
    def core(self):
        data = list(struct.unpack('<16I', b'expa' + self.key[:16] + b'nd 3' + self.iv.ljust(16, b'\x00') + b'2-by' + self.key[16:] + b'te k'))
        while 1:
            H = data[:]
            for a, b, c, d in ORDERS_SALSA20:
                H[a] ^= ROL(H[b]+H[c], 7)
                H[d] ^= ROL(H[a]+H[b], 9)
                H[c] ^= ROL(H[d]+H[a], 13)
                H[b] ^= ROL(H[c]+H[d], 18)
            yield from struct.pack('<16I', *(a+b&0xffffffff for a, b in zip(H, data)))
            data[8:10] = (0, data[9]+1) if data[8]==0xffffffff else (data[8]+1, data[9])

class CFBCipher(StreamCipher):
    """Base implementation for cipher-feedback mode adapters."""

    CIPHER: ClassVar[Any]
    bit_mode: bool
    last: int | None

    def setup(self):
        """Initialize the feedback-mode keystream and block primitive."""
        segment_bit = getattr(self, 'SEGMENT_SIZE', self.IV_LENGTH*8)
        self.bit_mode = segment_bit % 8 != 0
        self.stream = self.core_bit(segment_bit) if self.bit_mode else self.core(segment_bit//8)
        self.last = None
        self.cipher = self.CIPHER.new(self.key)
    def process(self, s, inv=False):
        """Encrypt or decrypt bytes through the feedback-mode keystream."""
        r = bytearray()
        for i in s:
            if self.bit_mode:
                j = 0
                for k in range(7,-1,-1):
                    ibit = i>>k & 1
                    jbit = ibit^self.stream.send(self.last)
                    j |= jbit<<k
                    self.last = ibit if inv else jbit
            else:
                j = i^self.stream.send(self.last)
                self.last = i if inv else j
            r.append(j)
        return bytes(r)
    def encrypt(self, s):
        return self.process(s, False)
    def decrypt(self, s):
        return self.process(s, True)
    def core(self, segment_byte):  # pylint: disable=arguments-differ
        """Yield feedback blocks for byte-oriented CFB operation."""
        next_iv = bytearray(self.iv)
        while 1:
            data = self.cipher.encrypt(next_iv)
            del next_iv[:segment_byte]
            for i in range(segment_byte):
                next_iv.append((yield data[i]))
    def core_bit(self, segment_bit):
        """Yield feedback bits for bit-oriented CFB operation."""
        next_iv = int.from_bytes(self.iv, 'big')
        mask = (1 << self.IV_LENGTH*8) - 1
        while 1:
            data = self.cipher.encrypt(next_iv)
            next_iv = next_iv<<segment_bit & mask
            for i in range(segment_bit):
                next_iv |= (yield data[i//8]>>(7-i%8)&1)<<(segment_bit-1-i)

class CFB8Cipher(CFBCipher):
    """CFB8 mode adapter for a pure-Python block cipher."""

    SEGMENT_SIZE = 8

class CFB1Cipher(CFBCipher):
    """CFB1 mode adapter for a pure-Python block cipher."""

    SEGMENT_SIZE = 1

class CTRCipher(StreamCipher):
    """Counter-mode adapter for a pure-Python block cipher."""

    CIPHER: ClassVar[Any]

    def setup(self):
        """Initialize the counter-mode keystream and block primitive."""
        self.stream = self.core()
        self.cipher = self.CIPHER.new(self.key)
    def core(self):
        """Yield successive encrypted counter blocks."""
        next_iv = int.from_bytes(self.iv, 'big')
        while 1:
            yield from self.cipher.encrypt(next_iv)
            next_iv = 0 if next_iv >= (1<<(self.IV_LENGTH*8))-1 else next_iv+1

class OFBCipher(CTRCipher):
    """Output-feedback mode adapter for a pure-Python block cipher."""

    def core(self):
        """Yield successive encrypted feedback blocks."""
        data = self.iv
        while 1:
            data = self.cipher.encrypt(data)
            yield from data

class GCMCipher(AEADCipher):
    """Pure-Python GCM authenticated-encryption adapter."""

    PYTHON = True
    NONCE_LENGTH = 12
    TAG_LENGTH = 16
    CIPHER: ClassVar[Any]
    hkey: list[int]
    def setup(self):
        """Initialize the block primitive and GCM hash subkey table."""
        self.cipher = self.CIPHER.new(self.key)
        self.hkey = []
        x = int.from_bytes(self.cipher.encrypt(0), 'big')
        for _ in range(128):
            self.hkey.insert(0, x)
            x = (x>>1)^(0xe1<<120) if x&1 else x>>1
    def process(self, s, tag=None):
        """Encrypt or authenticate one GCM packet."""
        def multh(y):
            z = 0
            for i in range(128):
                if y & (1<<i):
                    z ^= self.hkey[i]
            return z
        def ghash(d):
            dt = d + bytes((-len(d))%16)
            z = 0
            for i in range(0, len(dt), 16):
                z = multh(z^int.from_bytes(dt[i:i+16], 'big'))
            return multh(z^(len(d)*8))
        z = int.from_bytes(self.nonce, 'big')<<32
        h = int.from_bytes(self.cipher.encrypt(z|1), 'big')
        if tag is not None:
            require((ghash(s)^h).to_bytes(self.TAG_LENGTH, 'big') == tag)
        ret = bytes(s[i*16+j]^o for i in range((len(s)+15)//16) for j, o in enumerate(self.cipher.encrypt(z|(i+2)&((1<<32)-1))) if i*16+j < len(s))
        if tag is None:
            return ret, (ghash(ret)^h).to_bytes(self.TAG_LENGTH, 'big')
        return ret
    encrypt_and_digest = decrypt_and_verify = process

class RAW:  # pylint: disable=too-few-public-methods
    """Cacheable interface for pure-Python block cipher primitives."""

    CACHE = {}
    @classmethod
    def new(cls, key):
        """Return a cached block primitive for a key."""
        if key in cls.CACHE:
            return cls.CACHE[key]
        ret = cls.CACHE[key] = cls(key)
        return ret

class AES(RAW):
    """Pure-Python AES block cipher primitive."""

    g1 = base64.b64decode(b'Y3x3e/Jrb8UwAWcr/terdsqCyX36WUfwrdSir5ykcsC3/ZMmNj/3zDSl5fFx2DEVBMcjwxiWBZoHEoDi6yeydQmDLBobblqgUjvWsynjL4RT0QDtIPyxW2rLvjlKTFjP0O+q+0NNM4VF+QJ/UDyfqFGjQI+SnTj1vLbaIRD/89LNDBPsX5dEF8Snfj1kXRlzYIFP3CIqkIhG7rgU3l4L2+AyOgpJBiRcwtOsYpGV5HnnyDdtjdVOqWxW9Opleq4IunglLhymtMbo3XQfS72LinA+tWZIA/YOYTVXuYbBHZ7h+JgRadmOlJseh+nOVSjfjKGJDb/mQmhBmS0PsFS7Fg==')
    g2 = [a<<1&0xff^0x1b if a&0x80 else a<<1 for a in g1]
    g3 = [a^(a<<1&0xff^0x1b if a&0x80 else a<<1) for a in g1]
    Rcon = base64.b64decode(b'jQECBAgQIECAGzZs2KtNmi9evGPGlzVq1LN9+u/FkTly5NO9YcKfJUqUM2bMgx06dOjL')
    shifts = tuple((j,j&3|((j>>2)+(j&3))*4&12,j+3&3|((j>>2)+(j+3&3))*4&12,j+2&3|((j>>2)+(j+2&3))*4&12,j+1&3|((j>>2)+(j+1&3))*4&12) for j in range(16))
    def __init__(self, key):
        """Expand an AES key into the round-key schedule."""
        size, ekey = len(key), bytearray(key)
        nbr = {16:10, 24:12, 32:14}[size]
        while len(ekey) < 16*(nbr+1):
            t = ekey[-4:]
            if len(ekey) % size == 0:
                t = [self.g1[i] for i in t[1:]+t[:1]]
                t[0] ^= self.Rcon[len(ekey)//size%51]
            if size == 32 and len(ekey) % size == 16:
                t = [self.g1[i] for i in t]
            ekey.extend(m^ekey[i-size] for i, m in enumerate(t))
        self.ekey = tuple(ekey[i*16:i*16+16] for i in range(nbr+1))
    def encrypt(self, data):
        """Encrypt one AES block."""
        data = data.to_bytes(16, 'big') if isinstance(data, int) else data
        s = [data[j]^self.ekey[0][j] for j in range(16)]
        for key in self.ekey[1:-1]:
            s = [self.g2[s[a]]^self.g1[s[b]]^self.g1[s[c]]^self.g3[s[d]]^key[j] for j,a,b,c,d in self.shifts]
        return bytes([self.g1[s[self.shifts[j][1]]]^self.ekey[-1][j] for j in range(16)])

for method in (CFBCipher, CFB8Cipher, CFB1Cipher, CTRCipher, OFBCipher, GCMCipher):
    for key_size in (32, 24, 16):
        name = f'AES_{key_size*8}_{method.__name__[:-6]}_Cipher'
        globals()[name] = type(name, (method,), {'KEY_LENGTH': key_size, 'IV_LENGTH': key_size if method is GCMCipher else 16, 'CIPHER': AES})

class Blowfish(RAW):
    """Pure-Python Blowfish block cipher primitive."""

    P: ClassVar[list[int]] = []
    @staticmethod
    def hex_pi():
        """Yield hexadecimal digits of pi for Blowfish initialization."""
        n, d = -3, 1
        for xn, xd in ((120*N**2+151*N+47, 512*N**4+1024*N**3+712*N**2+194*N+15) for N in range(1<<32)):
            n, d = n * xd + d * xn, d * xd
            o, n = divmod(16 * n, d)
            yield f'{o:x}'
    def __init__(self, key):
        """Expand a Blowfish key into its P-array and S-box state."""
        if not self.P:
            pi = self.hex_pi()
            self.__class__.P = [int(''.join(next(pi) for j in range(8)), 16) for i in range(18+1024)]
        self.p = [a^b for a, b in zip(self.P[:18], struct.unpack('>18I', (key*(72//len(key)+1))[:72]))]+self.P[18:]
        buf = b'\x00'*8
        for i in range(0, 1042, 2):
            buf = self.encrypt(buf)
            self.p[i:i+2] = struct.unpack('>II', buf)
    def encrypt(self, s):
        """Encrypt one Blowfish block."""
        s = s.to_bytes(8, 'big') if isinstance(s, int) else s
        sl, sr = struct.unpack('>II', s)
        sl ^= self.p[0]
        for i in self.p[1:17]:
            sl, sr = sr ^ i ^ (self.p[18+(sl>>24)]+self.p[274+(sl>>16&0xff)]^self.p[530+(sl>>8&0xff)])+self.p[786+(sl&0xff)] & 0xffffffff, sl
        return struct.pack('>II', sr^self.p[17], sl)

class BF_CFB_Cipher(CFBCipher):
    """Blowfish CFB adapter using the pure-Python primitive."""

    KEY_LENGTH = 16
    IV_LENGTH = 8
    CIPHER = Blowfish

class Camellia(RAW):
    """Pure-Python Camellia block cipher primitive."""

    S1 = base64.b64decode(b'cIIs7LMnwOXkhVc16gyuQSPva5NFGaUh7Q5PTh1lkr2GuK+PfOsfzj4w3F9exQsapuE5ytVHXT3ZAVrWUVZsTYsNmmb7zLAtdBIrIPCxhJnfTMvCNH52BW23qTHRFwTXFFg6Yd4bERwyD5wWUxjyIv5Ez7LDtXqRJAjoqGD8aVCq0KB9oYlil1RbHpXg/2TSEMQASKP3dduKA+baCT/dlIdcgwLNSpAzc2f2851/v+JSm9gmyDfGO4GWb0sTvmMu6XmnjJ9uvI4p9fm2L/20WXiYBmrnRnG61CWrQoiijfpyB7lV+O6sCjZJKmg8OPGkQCjTe7vJQ8EV4630d8eAng==')
    S2, S3, S4 = bytes(i>>7|(i&0x7f)<<1 for i in S1), bytes(i>>1|(i&1)<<7 for i in S1), S1[::2]+S1[1::2]
    S = (S1, S4, S3, S2, S4, S3, S2, S1)
    KS = base64.b64decode(b'AAIICiAiKCpIShETGTM5OxIQQkBKSCMhKykAAgwOJCYoKkRGTE4RExkbMTM1Nz0/EhAaGEZESkgjIS8t')
    KS = tuple((i%16//4, i%4*32, (64,51,49,36,34)[i>>4]) for i in KS)
    def R(self, s, t):
        """Apply one Camellia round transformation."""
        t = sum(S[(t^s>>64)>>(i*8)&0xff]<<(i*8+32)%64 for i,S in enumerate(self.S))
        t = t^t>>32<<8&0xffffff00^t>>56^((t>>32<<56|t>>8)^t<<48)&0xffff<<48^(t>>8^t<<16)&0xffff<<32
        return (t^t>>8&0xff<<24^t>>40^t<<16&0xff<<56^t<<56^(t>>32<<48^t>>16^t<<24)&0xffffff<<32^s)<<64&(1<<128)-1|s>>64
    def __init__(self, key):
        """Expand a Camellia key into its round-key schedule."""
        q, R = [int.from_bytes(key[:16], 'big'), int.from_bytes(key[16:], 'big'), 0, 0], self.R
        q[1] = q[1]<<64|q[1]^((1<<64)-1) if len(key)==24 else q[1]
        q[2] = R(R(R(R(q[0]^q[1],0xa09e667f3bcc908b),0xb67ae8584caa73b2)^q[0],0xc6ef372fe94f82be),0x54ff53a5f1d36f1c)
        q[3] = R(R(q[2]^q[1],0x10e527fade682d1d),0xb05688c2b3e6c1fd)
        nr, ks = (22, self.KS[:26]) if len(key)==16 else (29, self.KS[26:])
        e = [(q[n]<<m>>o|q[n]>>128-m+o)&(1<<64)-1 for n, m, o in ks]
        self.e = [e[i+i//7]<<64|e[i+i//7+1] if i%7==0 else e[i+i//7+1] for i in range(nr)]
    def encrypt(self, s):
        """Encrypt one Camellia block."""
        s = (s if isinstance(s, int) else int.from_bytes(s, 'big'))^self.e[0]
        for idx, k in enumerate(self.e[1:-1]):
            s = s^((s&k)>>95&0xfffffffe|(s&k)>>127)<<64^((s&k)<<1&~1<<96^(s&k)>>31^s<<32|k<<32)&0xffffffff<<96 ^ ((s|k)&0xffffffff)<<32^((s|k)<<1^s>>31)&k>>31&0xfffffffe^((s|k)>>31^s>>63)&k>>63&1 if (idx+1)%7==0 else self.R(s, k)
        return (s>>64^(s&(1<<64)-1)<<64^self.e[-1]).to_bytes(16, 'big')

class Camellia_256_CFB_Cipher(CFBCipher):
    """Camellia-256 CFB adapter."""

    KEY_LENGTH = 32
    IV_LENGTH = 16
    CIPHER = Camellia

class Camellia_192_CFB_Cipher(Camellia_256_CFB_Cipher):
    """Camellia-192 CFB adapter."""

    KEY_LENGTH = 24

class Camellia_128_CFB_Cipher(Camellia_256_CFB_Cipher):
    """Camellia-128 CFB adapter."""

    KEY_LENGTH = 16

class IDEA(RAW):
    """Pure-Python IDEA block cipher primitive."""

    def __init__(self, key):
        """Expand an IDEA key into its subkey schedule."""
        e = list(struct.unpack('>8H', key))
        for i in range(8, 52):
            e.append((e[i-8&0xf8|i+1&0x7]&0x7f)<<9|e[i-8&0xf8|i+2&0x7]>>7)
        self.e = [e[i*6:i*6+6] for i in range(9)]
    def encrypt(self, s):
        """Encrypt one IDEA block."""
        s = s.to_bytes(8, 'big') if isinstance(s, int) else s
        def M(a, b):
            """Apply IDEA multiplication modulo 65537."""
            return (a*b-(a*b>>16)+(a*b&0xffff<a*b>>16) if a else 1-b if b else 1-a)&0xffff
        s0, s1, s2, s3 = struct.unpack('>4H', s)
        for e in self.e[:-1]:
            s0, o1, o2, s3 = M(s0, e[0]), s1+e[1], s2+e[2]&0xffff, M(s3, e[3])
            s2 = M(o2^s0, e[4])
            s1 = M((o1^s3)+s2&0xffff, e[5])
            s0, s1, s2, s3 = s0^s1, s1^o2, s2+s1^o1, s3^s2+s1&0xffff
        e = self.e[-1]
        return struct.pack('>4H', M(s0, e[0]), s2+e[1]&0xffff, s1+e[2]&0xffff, M(s3, e[3]))

class IDEA_CFB_Cipher(CFBCipher):
    """IDEA CFB adapter using the pure-Python primitive."""

    KEY_LENGTH = 16
    IV_LENGTH = 8
    CIPHER = IDEA

class SEED(RAW):
    """Pure-Python SEED block cipher primitive."""

    S0 = base64.b64decode(b'qYXW01QdrCVdQxgeUfzKYyhEIJ3g4sgXpY8De7sT0u5wjD+oMt32dOyVC1dcW70BJBxzmBDM8tks53KDm9GGyWBQo+sNtp5Pt1rGeKYSr9Vhw7RBUn2NCB+ZABkEU/fh/XYvJ7CLDquibpNNaXwJCr/v88WHFP5k3i5LGgYha2YC9ZKKDLN+0HpHluUmgK3foTA3rjYVIjj0p0VMgemElzXLzjxxEceJdfva+JRZgsT/STlnwM/XuA+OQiORbNukNPFIwm89LUC+PrzBqrpOVTvcaH+c2EpWd6DtRrUrZfrjubGfXvnmsjHqbV/k8M2IFjpY1GIpBzPoGwV5kGoqmg==')
    S1 = base64.b64decode(b'OOgtps/es7ivYFXHRG9rW8NiM7UpoOKn05ERBhy8NkvviGyoF8QW9MJF4dY/PY6YKE72PqX5Dd/YK2Z6Jy/xckLUQcBzZ6yL962AH8osqjTSC+7pXZQY+FeuCMUTzYa5/33BMfWKarHRINcCIgRocQfbnZlhvuZZ3VGQ3Jqjq9CBD0ca4+yNv5Z7XKKhYyNNyJ6cOgwuum6fWvKS80l4zBX7cHV/NRADZG3GdNW06gl2Gf5AEuC9BfoB8CpeqVZDhRSJm7DlSHmX/B6CIYwbX3dUsh0lTwBG7VhS637ayf0wlWU8tuS7fA5QOSYyhGmTN+ckpMtTCofZTIOPzjtKtw==')
    def G(self, x, M=b'\xfc\xf3\xcf\x3f'):
        """Apply the SEED substitution and permutation transform."""
        return sum(
            (self.S0[x&0xff]&M[i]^self.S1[x>>8&0xff]&M[i+1&3]
             ^self.S0[x>>16&0xff]&M[i+2&3]^self.S1[x>>24&0xff]&M[i+3&3])<<i*8
            for i in range(4)
        )
    def __init__(self, key):
        """Expand a SEED key into its round-key schedule."""
        self.e, key0, key1 = [], *struct.unpack('>QQ', key)
        for i, kc in enumerate((0x9e3779b9, 0x3c6ef373, 0x78dde6e6, 0xf1bbcdcc, 0xe3779b99, 0xc6ef3733, 0x8dde6e67, 0x1bbcdccf, 0x3779b99e, 0x6ef3733c, 0xdde6e678, 0xbbcdccf1, 0x779b99e3, 0xef3733c6, 0xde6e678d, 0xbcdccf1b)):
            self.e.append((self.G((key0>>32)+(key1>>32)-kc), self.G(key0-key1+kc)))
            key0, key1 = (key0, (key1<<8|key1>>56)&(1<<64)-1) if i&1 else ((key0<<56|key0>>8)&(1<<64)-1, key1)
    def encrypt(self, s):
        """Encrypt one SEED block."""
        s = s.to_bytes(16, 'big') if isinstance(s, int) else s
        s0, s1, s2, s3 = struct.unpack('>4I', s)
        for k0, k1 in self.e:
            t0 = self.G(s2^k0^s3^k1)
            t1 = self.G(t0+(s2^k0))
            t0 = self.G(t1+t0)
            s0, s1, s2, s3 = s2, s3, s0^t0+t1, s1^t0
        return struct.pack('>4I', s2&0xffffffff, s3, s0&0xffffffff, s1)

class SEED_CFB_Cipher(CFBCipher):
    """SEED CFB adapter using the pure-Python primitive."""

    KEY_LENGTH = 16
    IV_LENGTH = 16
    CIPHER = SEED

class RC2(RAW):
    """Pure-Python RC2 block cipher primitive."""

    S = base64.b64decode(b'2Xj5xBndte0o6f15SqDYncZ+N4MrdlOOYkxkiESL+6IXmln1h7NPE2FFbY0JgX0yvY9A64a3ewvwlSEiXGtOglTWZZPOYLIcc1bAFKeM8dwSdcofO77k0UI91DCjPLYmb78O2kZpB1cn8h2bvJRDA/gRx/aQ7z7nBsPVL8hmHtcI6OregFLu94Sqcqw1TWoqlhrScVoVSXRLn9BeBBik7MLgQW4PUcvMJJGvUKH0cDmZfDqFI7i0evwCNlslVZcxLV36mOOKkq4F3ykQZ2y6ydMA5s/hnqgsYxYBP1jiiakNODQbqzP/sLtIDF+5sc0uxfPbR+WlnHcKpiBo/n/BrQ==')
    B = list(range(20))+[-4,-3,-2,-1]+list(range(20,44))+[-4,-3,-2,-1]+list(range(44,64))
    def __init__(self, key):
        """Expand an RC2 key into its effective key schedule."""
        e = bytearray(key)
        for i in range(128-len(key)):
            e.append(self.S[e[-1]+e[-len(key)]&0xff])
        e[-len(key)] = self.S[e[-len(key)]]
        for i in range(127-len(key), -1, -1):
            e[i] = self.S[e[i+1]^e[i+len(key)]]
        self.e = struct.unpack('<64H', e)
    def encrypt(self, s):
        """Encrypt one RC2 block."""
        s = s.to_bytes(8, 'big') if isinstance(s, int) else s
        s = list(struct.unpack('<4H', s))
        for j in self.B:
            s[j&3] = s[j&3]+self.e[j]+(s[j+3&3]&s[j+2&3])+(~s[j+3&3]&s[j+1&3])<<j%4*4//3+1&0xffff|(s[j&3]+self.e[j]+(s[j+3&3]&s[j+2&3])+(~s[j+3&3]&s[j+1&3])&0xffff)>>15-j%4*4//3 if j>=0 else s[j]+self.e[s[j+3]&0x3f]
        return struct.pack('<4H', *s)

class RC2_CFB_Cipher(CFBCipher):
    """RC2 CFB adapter using the pure-Python primitive."""

    KEY_LENGTH = 16
    IV_LENGTH = 8
    CIPHER = RC2

MAP = {cls.name(): cls for name, cls in globals().items() if name.endswith('_Cipher')}
