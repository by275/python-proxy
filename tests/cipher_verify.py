"""Verify cipher round trips and serialized compatibility vectors."""

import os
import pickle
import sys
import time
from pproxy.cipher import MAP
from pproxy.cipherpy import MAP as MAP_PY

def test_both_cipher(cipher_a, cipher_b, size=4*1024, repeat=16):
    print('Testing', cipher_b.__name__, '...')
    t1 = t2 = 0
    for _ in range(repeat):
        assert cipher_a.KEY_LENGTH == cipher_b.KEY_LENGTH and cipher_a.IV_LENGTH == cipher_b.IV_LENGTH
        key = os.urandom(cipher_a.KEY_LENGTH)
        iv = os.urandom(cipher_a.IV_LENGTH)
        t = time.perf_counter()
        a = cipher_a(key)
        a.setup_iv(iv)
        t1 += time.perf_counter() - t
        t = time.perf_counter()
        b = cipher_b(key)
        b.setup_iv(iv)
        t2 += time.perf_counter() - t
        s = os.urandom(size)
        t = time.perf_counter()
        s2 = a.encrypt(s)
        t1 += time.perf_counter() - t
        t = time.perf_counter()
        s3 = b.encrypt(s)
        t2 += time.perf_counter() - t
        assert s2 == s3

        t = time.perf_counter()
        a = cipher_a(key, True)
        a.setup_iv(iv)
        t1 += time.perf_counter() - t
        t = time.perf_counter()
        b = cipher_b(key, True)
        b.setup_iv(iv)
        t2 += time.perf_counter() - t
        t = time.perf_counter()
        s4 = a.decrypt(s2)
        t1 += time.perf_counter() - t
        t = time.perf_counter()
        s5 = b.decrypt(s2)
        t2 += time.perf_counter() - t
        assert s4 == s5 == s

    print('Passed', t1, t2)

def test_cipher(cipher_class, known_vectors, size=4*1024, repeat=16):
    if cipher_class.__name__ not in known_vectors:
        if input('Correct now? (Y/n)').upper() != 'Y':
            return
        d = []
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
            d.append((key, iv, s, s2))
        known_vectors[cipher_class.__name__] = d
        print('Saved correct data')
    else:
        t = time.perf_counter()
        print('Testing', cipher_class.__name__, '...')
        for key, iv, s, s2 in known_vectors[cipher_class.__name__]:
            a = cipher_class(key)
            a.setup_iv(iv)
            s3 = a.encrypt(s)
            assert s2 == s3
            a = cipher_class(key, True)
            a.setup_iv(iv)
            s4 = a.decrypt(s2)
            assert s == s4
        print('Passed', time.perf_counter()-t)


cipher = sys.argv[1] if len(sys.argv) > 1 else None
data = pickle.load(open('.cipherdata', 'rb')) if os.path.exists('.cipherdata') else {}

if cipher is None:
    print('Testing all ciphers')

    for cipher, B in sorted(MAP_PY.items()):
        A = MAP.get(cipher)
        if A:
            test_both_cipher(A, B)
        elif B.__name__ in data:
            test_cipher(B, data)
else:
    B = MAP_PY[cipher]
    A = MAP.get(cipher)
    if A:
        test_both_cipher(A, B)
    else:
        test_cipher(B, data)


pickle.dump(data, open('.cipherdata', 'wb'))
