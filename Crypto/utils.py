import json
import os
import socket
from Crypto.Random import get_random_bytes


def read_until(s, suffix):
    res = b''
    while not res.endswith(suffix):
        # quite slow, but should be enough for us
        d = s.recv(1)
        if len(d) == 0:
            raise EOFError()
        res += d
    return res


class LcgPrng:
    a = 672257317069504227
    c = 7382843889490547368
    m = 9223372036854775783

    def __init__(self, seed):
        self.state = seed

    def next(self):
        """Gets a next 64bit random number."""
        self.state = (self.state * self.a + self.c) % self.m
        return self.state

    def next_bytes(self):
        """Gets 7 random bytes.
        Even though internal state is 64bit (8 bytes), we don't actually
        get 64 bits of entropy per next(). Due to how LCGs work, some
        values are unobtainable, for example next() will never
        return 2**64 - 1. Returning just 7 bytes works around this problem
        (it's still biased, but there's just a tiny bit of bias left).
        """
        rnd_56bit = self.next() & 0xFFFFFFFFFFFFFF
        return rnd_56bit.to_bytes(7, 'little')


def lcg_encrypt(key, data):
    """Encrypt the data using a LCG-based stream cipher."""
    cipher = LcgPrng(key)
    keystream = b''
    while len(keystream) < len(data):
        keystream += cipher.next_bytes()
    # print('late_key & keystream:', key, keystream)
    return xor(keystream, data)


def xor(a, b):
    return bytes([ac ^ bc for ac, bc in zip(a, b)])


def split_by(data, cnt):
    return [data[i : i+cnt] for i in range(0, len(data), cnt)]


def pad(msg):
    byte = 16 - len(msg) % 16
    return msg + bytes([byte] * byte)


def unpad(msg):
    if not msg:
        return b''
    return msg[:-msg[-1]]


def ae_encrypt(aes, msg):
    msg = pad(msg)
    iv = get_random_bytes(16)
    prev_pt = iv
    prev_ct = iv
    ct = b''
    for pt_block in split_by(msg, 16) + [iv]:
        ct_block = xor(prev_pt, aes.encrypt(xor(pt_block, prev_ct)))
        ct += ct_block
        prev_pt = pt_block
        prev_ct = ct_block
    return iv + ct


def ae_decrypt(aes, msg):
    """Returns a tuple: decrypted message, signature validation result.
    """
    iv, msg = msg[:16], msg[16:]
    prev_pt = iv
    prev_ct = iv
    pt = b''
    for ct_block in split_by(msg, 16):
        pt_block = xor(prev_ct, aes.decrypt(xor(ct_block, prev_pt)))
        pt += pt_block
        prev_pt = pt_block
        prev_ct = ct_block
    pt, tag = pt[:-16], pt[-16:]
    return unpad(pt), tag == iv
