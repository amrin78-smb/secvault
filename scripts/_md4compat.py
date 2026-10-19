"""
Pure-Python MD4, registered as a hashlib fallback.

⛔ WHY THIS EXISTS. NTLM's NT hash is MD4(password-as-UTF-16LE) -- that is the
protocol, not a choice -- and `ntlm_auth` reaches it through
`hashlib.new('md4', ...)`. OpenSSL 3 moved MD4 into the legacy provider and
Ubuntu 24.04 does not load it, so on this box that call raises
"unsupported hash type md4" and every WinRM connection dies before it starts.

⛔ THE ALTERNATIVE WAS REFUSED. Enabling the OpenSSL legacy provider would
re-enable MD4 (and MD2, RC4, DES) process-wide for every program on the
machine, to fix one client. A 40-line function here changes nothing outside
this script.

⛔ AND IT SELF-VERIFIES BEFORE IT INSTALLS, WHICH IS LOAD-BEARING. A subtly
wrong MD4 does not crash -- it returns 16 plausible bytes, the server rejects
the response, and the helper reports "credentials rejected". That is a correct
password presented as a wrong one, and on a domain account each retry spends a
real LOCKOUT STRIKE chasing a bug in this file. So the RFC 1320 vectors are
checked at registration and a mismatch refuses to install the shim rather than
letting it run.

MD4 is used here ONLY because NTLM specifies it. It is not a security choice
and must never be reused for anything else.
"""
import hashlib
import struct

_M = 0xffffffff


def _lrot(x, n):
    x &= _M
    return ((x << n) | (x >> (32 - n))) & _M


def md4(message: bytes) -> bytes:
    h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

    msg = bytearray(message)
    bit_len = (8 * len(message)) & 0xffffffffffffffff
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += struct.pack('<Q', bit_len)

    for off in range(0, len(msg), 64):
        X = struct.unpack('<16I', bytes(msg[off:off + 64]))
        a, b, c, d = h

        # Round 1 -- F(x,y,z) = (x & y) | (~x & z)
        for i in range(16):
            s = (3, 7, 11, 19)[i % 4]
            if i % 4 == 0:
                a = _lrot(a + (((b & c) | (~b & d)) & _M) + X[i], s)
            elif i % 4 == 1:
                d = _lrot(d + (((a & b) | (~a & c)) & _M) + X[i], s)
            elif i % 4 == 2:
                c = _lrot(c + (((d & a) | (~d & b)) & _M) + X[i], s)
            else:
                b = _lrot(b + (((c & d) | (~c & a)) & _M) + X[i], s)

        # Round 2 -- G(x,y,z) = (x&y) | (x&z) | (y&z), k = 0,4,8,12,1,5,...
        order2 = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
        for i, k in enumerate(order2):
            s = (3, 5, 9, 13)[i % 4]
            if i % 4 == 0:
                a = _lrot(a + (((b & c) | (b & d) | (c & d)) & _M) + X[k] + 0x5a827999, s)
            elif i % 4 == 1:
                d = _lrot(d + (((a & b) | (a & c) | (b & c)) & _M) + X[k] + 0x5a827999, s)
            elif i % 4 == 2:
                c = _lrot(c + (((d & a) | (d & b) | (a & b)) & _M) + X[k] + 0x5a827999, s)
            else:
                b = _lrot(b + (((c & d) | (c & a) | (d & a)) & _M) + X[k] + 0x5a827999, s)

        # Round 3 -- H(x,y,z) = x ^ y ^ z, k = 0,8,4,12,2,10,...
        order3 = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for i, k in enumerate(order3):
            s = (3, 9, 11, 15)[i % 4]
            if i % 4 == 0:
                a = _lrot(a + ((b ^ c ^ d) & _M) + X[k] + 0x6ed9eba1, s)
            elif i % 4 == 1:
                d = _lrot(d + ((a ^ b ^ c) & _M) + X[k] + 0x6ed9eba1, s)
            elif i % 4 == 2:
                c = _lrot(c + ((d ^ a ^ b) & _M) + X[k] + 0x6ed9eba1, s)
            else:
                b = _lrot(b + ((c ^ d ^ a) & _M) + X[k] + 0x6ed9eba1, s)

        h = [(h[0] + a) & _M, (h[1] + b) & _M, (h[2] + c) & _M, (h[3] + d) & _M]

    return struct.pack('<4I', *h)


class _MD4Hash:
    """The sliver of the hashlib interface that ntlm_auth actually uses."""
    name = 'md4'
    digest_size = 16
    block_size = 64

    def __init__(self, data: bytes = b''):
        self._buf = bytearray(data)

    def update(self, data: bytes):
        self._buf += data

    def digest(self) -> bytes:
        return md4(bytes(self._buf))

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self):
        return _MD4Hash(bytes(self._buf))


# RFC 1320, appendix A.5. The first is also the NT hash of an empty password,
# which is the value this shim exists to produce.
_VECTORS = {
    b'': '31d6cfe0d16ae931b73c59d7e0c089c0',
    b'a': 'bde52cb31de33e46245e05fbdbd6fb24',
    b'abc': 'a448017aaf21d8525fc10ae87aa6729d',
    b'message digest': 'd9130a8164549fe818874806e1c7014b',
    b'abcdefghijklmnopqrstuvwxyz': 'd79e1c308aa5bbcdeea8ed63df412da9',
    b'12345678901234567890123456789012345678901234567890'
    b'123456789012345678901234567890': 'e33b4ddc9c38f2199c3e7b164fcc0536',
}


def selftest():
    """Raise unless every RFC 1320 vector matches. Never silently pass."""
    for msg, want in _VECTORS.items():
        got = md4(msg).hex()
        if got != want:
            raise RuntimeError(
                f'MD4 self-test FAILED for {msg[:20]!r}: got {got}, want {want}')
    return True


def install():
    """
    Make hashlib.new('md4') work. Returns 'native' if it already did,
    'shim' if this implementation was installed.

    ⛔ Never installs an unverified implementation -- see the module docstring.
    """
    try:
        hashlib.new('md4')
        return 'native'
    except (ValueError, TypeError):
        pass

    selftest()

    _orig_new = hashlib.new

    def _new(name, data=b'', **kw):
        if str(name).lower().replace('-', '') == 'md4':
            return _MD4Hash(data)
        return _orig_new(name, data, **kw)

    hashlib.new = _new
    if not hasattr(hashlib, 'md4'):
        hashlib.md4 = _MD4Hash
    return 'shim'
