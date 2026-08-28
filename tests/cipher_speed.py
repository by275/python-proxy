import os
import sys
import time
from pproxy.cipher import MAP
from pproxy.cipherpy import MAP as MAP_PY

def test_cipher(cipher_class, size=32*1024, repeat=128):
    for _ in range(repeat):
        key = os.urandom(cipher_class.KEY_LENGTH)
        iv = os.urandom(cipher_class.IV_LENGTH)
        a = cipher_class(key)
        a.setup_iv(iv)
        s = os.urandom(size)
        s2 = a.encrypt(s)
        a = cipher_class(key, True)
        a.setup_iv(iv)
        s4 = a.decrypt(s2)
        assert s == s4

cipher = sys.argv[1] if len(sys.argv) > 1 else None

if cipher and cipher.endswith('-py'):
    A = MAP_PY.get(cipher[:-3])
else:
    A = MAP.get(cipher)
if A:
    t = time.perf_counter()
    test_cipher(A)
    print(cipher, time.perf_counter()-t)
else:
    print('unknown cipher', cipher)
