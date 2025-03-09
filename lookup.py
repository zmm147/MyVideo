#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
综合文件，包含 ripemd128、pureSalsa20 和 readmdict 三个文件的代码。
"""

# =================== ripemd128.py ==================
"""
Copyright by https://github.com/zhansliu/writemdict

ripemd128.py - A simple ripemd128 library in pure Python.

支持 Python2(>=2.6) 和 Python3。

使用示例:
    from ripemd128 import ripemd128
    digest = ripemd128(b"The quick brown fox jumps over the lazy dog")
    assert(digest == b"\x3f\xa9\xb5\x7f\x05\x3c\x05\x3f\xbe\x27\x35\xb2\x38\x0d\xb5\x96")
"""
import struct

def f(j, x, y, z):
    assert(0 <= j and j < 64)
    if j < 16:
        return x ^ y ^ z
    elif j < 32:
        return (x & y) | (z & ~x)
    elif j < 48:
        return (x | (0xffffffff & ~y)) ^ z
    else:
        return (x & z) | (y & ~z)

def K(j):
    assert(0 <= j and j < 64)
    if j < 16:
        return 0x00000000
    elif j < 32:
        return 0x5a827999
    elif j < 48:
        return 0x6ed9eba1
    else:
        return 0x8f1bbcdc

def Kp(j):
    assert(0 <= j and j < 64)
    if j < 16:
        return 0x50a28be6
    elif j < 32:
        return 0x5c4dd124
    elif j < 48:
        return 0x6d703ef3
    else:
        return 0x00000000

def padandsplit(message):
    """
    返回二维数组 X[i][j] (每个值为32位整数)，先对消息做填充（使长度模64余56），再附加消息长度的64位小端表示，
    最后将填充后的消息分成64字节块，每块解析为4字节的整数。
    """
    origlen = len(message)
    padlength = 64 - ((origlen - 56) % 64)  # 至少填充1个字节
    message += b"\x80"
    message += b"\x00" * (padlength - 1)
    message += struct.pack("<Q", origlen*8)
    assert(len(message) % 64 == 0)
    return [
        [struct.unpack("<L", message[i+j:i+j+4])[0]
         for j in range(0, 64, 4)]
        for i in range(0, len(message), 64)
    ]

def add(*args):
    return sum(args) & 0xffffffff

def rol(s, x):
    assert(s < 32)
    return (x << s | x >> (32-s)) & 0xffffffff

r = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
     7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
     3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
     1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2]
rp = [5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
      6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
      15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
      8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14]
s = [11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
     7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
     11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
     11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12]
sp = [8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
      9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
      9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
      15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8]

def ripemd128(message):
    h0 = 0x67452301
    h1 = 0xefcdab89
    h2 = 0x98badcfe
    h3 = 0x10325476
    X = padandsplit(message)
    for i in range(len(X)):
        (A, B, C, D) = (h0, h1, h2, h3)
        (Ap, Bp, Cp, Dp) = (h0, h1, h2, h3)
        for j in range(64):
            T = rol(s[j], add(A, f(j, B, C, D), X[i][r[j]], K(j)))
            (A, D, C, B) = (D, C, B, T)
            T = rol(sp[j], add(Ap, f(63-j, Bp, Cp, Dp), X[i][rp[j]], Kp(j)))
            (Ap, Dp, Cp, Bp) = (Dp, Cp, Bp, T)
        T = add(h1, C, Dp)
        h1 = add(h2, D, Ap)
        h2 = add(h3, A, Bp)
        h3 = add(h0, B, Cp)
        h0 = T
    return struct.pack("<LLLL", h0, h1, h2, h3)

def hexstr(bstr):
    return "".join("{0:02x}".format(b) for b in bstr)

# =================== pureSalsa20.py ==================
"""
pureSalsa20.py -- pure Python 实现的 Salsa20 流密码（只包含 Salsa20 部分）。
"""
import sys
assert(sys.version_info >= (2, 6))

if sys.version_info >= (3,):
    integer_types = (int,)
    python3 = True
else:
    integer_types = (int, long)
    python3 = False

from struct import Struct
little_u64 = Struct("<Q")      # 小端64位无符号
little16_i32 = Struct("<16i")   # 16个小端32位整数
little4_i32 = Struct("<4i")
little2_i32 = Struct("<2i")

_version = 'p4.0'

class Salsa20(object):
    def __init__(self, key=None, IV=None, rounds=20):
        self._lastChunk64 = True
        self._IVbitlen = 64  # 必须为64位
        self.ctx = [0] * 16
        if key:
            self.setKey(key)
        if IV:
            self.setIV(IV)
        self.setRounds(rounds)

    def setKey(self, key):
        assert(type(key) == bytes)
        ctx = self.ctx
        if len(key) == 32:
            constants = b"expand 32-byte k"
            ctx[1], ctx[2], ctx[3], ctx[4] = little4_i32.unpack(key[0:16])
            ctx[11], ctx[12], ctx[13], ctx[14] = little4_i32.unpack(key[16:32])
        elif len(key) == 16:
            constants = b"expand 16-byte k"
            ctx[1], ctx[2], ctx[3], ctx[4] = little4_i32.unpack(key[0:16])
            ctx[11], ctx[12], ctx[13], ctx[14] = little4_i32.unpack(key[0:16])
        else:
            raise Exception("key length isn't 32 or 16 bytes.")
        ctx[0], ctx[5], ctx[10], ctx[15] = little4_i32.unpack(constants)

    def setIV(self, IV):
        assert(type(IV) == bytes)
        assert(len(IV)*8 == 64, 'nonce (IV) 不是64位')
        self.IV = IV
        ctx = self.ctx
        ctx[6], ctx[7] = little2_i32.unpack(IV)
        ctx[8], ctx[9] = 0, 0  # 重置计数器

    setNonce = setIV

    def setCounter(self, counter):
        assert(type(counter) in integer_types)
        assert(0 <= counter < 1<<64), "counter < 0 or >= 2**64"
        ctx = self.ctx
        ctx[8], ctx[9] = little2_i32.unpack(little_u64.pack(counter))

    def getCounter(self):
        return little_u64.unpack(little2_i32.pack(*self.ctx[8:10]))[0]

    def setRounds(self, rounds, testing=False):
        assert(testing or rounds in [8, 12, 20]), 'rounds must be 8, 12, 20'
        self.rounds = rounds

    def encryptBytes(self, data):
        assert(type(data) == bytes, 'data 必须是字节串')
        assert(self._lastChunk64, '上一个块长度不是64字节的倍数')
        lendata = len(data)
        munged = bytearray(lendata)
        for i in range(0, lendata, 64):
            h = salsa20_wordtobyte(self.ctx, self.rounds, checkRounds=False)
            self.setCounter((self.getCounter() + 1) % 2**64)
            for j in range(min(64, lendata - i)):
                if python3:
                    munged[i+j] = data[i+j] ^ h[j]
                else:
                    munged[i+j] = ord(data[i+j]) ^ ord(h[j])
        self._lastChunk64 = not (lendata % 64)
        return bytes(munged)

    decryptBytes = encryptBytes  # 加解密函数相同

def salsa20_wordtobyte(input, nRounds=20, checkRounds=True):
    """
    对 input（长度16的整数列表或元组）做 nRounds 轮 Salsa20 运算，返回64字节结果。
    """
    assert(type(input) in (list, tuple) and len(input) == 16)
    assert(not checkRounds or (nRounds in [8, 12, 20]))
    x = list(input)
    def XOR(a, b): return a ^ b
    ROTATE = rot32
    PLUS = add32
    for i in range(nRounds // 2):
        x[4] = XOR(x[4], ROTATE(PLUS(x[0], x[12]), 7))
        x[8] = XOR(x[8], ROTATE(PLUS(x[4], x[0]), 9))
        x[12] = XOR(x[12], ROTATE(PLUS(x[8], x[4]), 13))
        x[0] = XOR(x[0], ROTATE(PLUS(x[12], x[8]), 18))
        x[9] = XOR(x[9], ROTATE(PLUS(x[5], x[1]), 7))
        x[13] = XOR(x[13], ROTATE(PLUS(x[9], x[5]), 9))
        x[1] = XOR(x[1], ROTATE(PLUS(x[13], x[9]), 13))
        x[5] = XOR(x[5], ROTATE(PLUS(x[1], x[13]), 18))
        x[14] = XOR(x[14], ROTATE(PLUS(x[10], x[6]), 7))
        x[2] = XOR(x[2], ROTATE(PLUS(x[14], x[10]), 9))
        x[6] = XOR(x[6], ROTATE(PLUS(x[2], x[14]), 13))
        x[10] = XOR(x[10], ROTATE(PLUS(x[6], x[2]), 18))
        x[3] = XOR(x[3], ROTATE(PLUS(x[15], x[11]), 7))
        x[7] = XOR(x[7], ROTATE(PLUS(x[3], x[15]), 9))
        x[11] = XOR(x[11], ROTATE(PLUS(x[7], x[3]), 13))
        x[15] = XOR(x[15], ROTATE(PLUS(x[11], x[7]), 18))

        x[1] = XOR(x[1], ROTATE(PLUS(x[0], x[3]), 7))
        x[2] = XOR(x[2], ROTATE(PLUS(x[1], x[0]), 9))
        x[3] = XOR(x[3], ROTATE(PLUS(x[2], x[1]), 13))
        x[0] = XOR(x[0], ROTATE(PLUS(x[3], x[2]), 18))
        x[6] = XOR(x[6], ROTATE(PLUS(x[5], x[4]), 7))
        x[7] = XOR(x[7], ROTATE(PLUS(x[6], x[5]), 9))
        x[4] = XOR(x[4], ROTATE(PLUS(x[7], x[6]), 13))
        x[5] = XOR(x[5], ROTATE(PLUS(x[4], x[7]), 18))
        x[11] = XOR(x[11], ROTATE(PLUS(x[10], x[9]), 7))
        x[8] = XOR(x[8], ROTATE(PLUS(x[11], x[10]), 9))
        x[9] = XOR(x[9], ROTATE(PLUS(x[8], x[11]), 13))
        x[10] = XOR(x[10], ROTATE(PLUS(x[9], x[8]), 18))
        x[12] = XOR(x[12], ROTATE(PLUS(x[15], x[14]), 7))
        x[13] = XOR(x[13], ROTATE(PLUS(x[12], x[15]), 9))
        x[14] = XOR(x[14], ROTATE(PLUS(x[13], x[12]), 13))
        x[15] = XOR(x[15], ROTATE(PLUS(x[14], x[13]), 18))
    for i in range(len(input)):
        x[i] = add32(x[i], input[i])
    return little16_i32.pack(*x)

def trunc32(w):
    """返回整数 w 的低32位。"""
    w = int((w & 0x7fffFFFF) | -(w & 0x80000000))
    assert(type(w) == int)
    return w

def add32(a, b):
    lo = (a & 0xFFFF) + (b & 0xFFFF)
    hi = (a >> 16) + (b >> 16) + (lo >> 16)
    return ((-(hi & 0x8000)) | (hi & 0x7FFF)) << 16 | (lo & 0xFFFF)

def rot32(w, nLeft):
    nLeft &= 31
    if nLeft == 0:
        return w
    RRR = (((w >> 1) & 0x7fffFFFF) >> (31 - nLeft))
    sLLLLLL = -((1 << (31 - nLeft)) & w) | ((0x7fffFFFF >> nLeft) & w)
    return RRR | (sLLLLLL << nLeft)

# =================== readmdict.py ==================
"""
readmdict.py
用于解析 Octopus MDict 字典文件 (.mdx) 和资源文件 (.mdd)。
"""
from struct import pack, unpack
from io import BytesIO
import re
import sys
import zlib

try:
    import lzo
except ImportError:
    lzo = None
    print("LZO compression support is not available")

if sys.hexversion >= 0x03000000:
    unicode = str

def _unescape_entities(text):
    """反转义 &lt; &gt; &quot; &amp;"""
    text = text.replace(b'&lt;', b'<')
    text = text.replace(b'&gt;', b'>')
    text = text.replace(b'&quot;', b'"')
    text = text.replace(b'&amp;', b'&')
    return text

def _fast_decrypt(data, key):
    b_array = bytearray(data)
    key = bytearray(key)
    previous = 0x36
    for i in range(len(b_array)):
        t = (b_array[i] >> 4 | b_array[i] << 4) & 0xff
        t = t ^ previous ^ (i & 0xff) ^ key[i % len(key)]
        previous = b_array[i]
        b_array[i] = t
    return bytes(b_array)

def _mdx_decrypt(comp_block):
    key = ripemd128(comp_block[4:8] + pack(b'<L', 0x3695))
    return comp_block[0:8] + _fast_decrypt(comp_block[8:], key)

def _salsa_decrypt(ciphertext, encrypt_key):
    s20 = Salsa20(key=encrypt_key, IV=b"\x00"*8, rounds=8)
    return s20.encryptBytes(ciphertext)

def _decrypt_regcode_by_deviceid(reg_code, deviceid):
    deviceid_digest = ripemd128(deviceid)
    s20 = Salsa20(key=deviceid_digest, IV=b"\x00"*8, rounds=8)
    encrypt_key = s20.encryptBytes(reg_code)
    return encrypt_key

def _decrypt_regcode_by_email(reg_code, email):
    email_digest = ripemd128(email.decode().encode('utf-16-le'))
    s20 = Salsa20(key=email_digest, IV=b"\x00"*8, rounds=8)
    encrypt_key = s20.encryptBytes(reg_code)
    return encrypt_key

class MDict(object):
    """
    基础类，用于读取 header 和 key block。
    仅供代码共享，不提供公共接口。
    """
    def __init__(self, fname, encoding='', passcode=None):
        self._fname = fname
        self._encoding = encoding.upper()
        self._passcode = passcode
        self.header = self._read_header()
        try:
            self._key_list = self._read_keys()
        except Exception:
            print("Try Brutal Force on Encrypted Key Blocks")
            self._key_list = self._read_keys_brutal()

    def __len__(self):
        return self._num_entries

    def __iter__(self):
        return self.keys()

    def keys(self):
        """返回所有字典键的迭代器。"""
        return (key_value for key_id, key_value in self._key_list)

    def _read_number(self, f):
        return unpack(self._number_format, f.read(self._number_width))[0]

    def _parse_header(self, header):
        taglist = re.findall(b'(\w+)="(.*?)"', header, re.DOTALL)
        tagdict = {}
        for key, value in taglist:
            tagdict[key] = _unescape_entities(value)
        return tagdict

    def _decode_key_block_info(self, key_block_info_compressed):
        if self._version >= 2:
            assert(key_block_info_compressed[:4] == b'\x02\x00\x00\x00')
            if self._encrypt & 0x02:
                key_block_info_compressed = _mdx_decrypt(key_block_info_compressed)
            key_block_info = zlib.decompress(key_block_info_compressed[8:])
            adler32 = unpack('>I', key_block_info_compressed[4:8])[0]
            assert(adler32 == zlib.adler32(key_block_info) & 0xffffffff)
        else:
            key_block_info = key_block_info_compressed
        key_block_info_list = []
        num_entries = 0
        i = 0
        if self._version >= 2:
            byte_format = '>H'
            byte_width = 2
            text_term = 1
        else:
            byte_format = '>B'
            byte_width = 1
            text_term = 0
        while i < len(key_block_info):
            num_entries += unpack(self._number_format, key_block_info[i:i+self._number_width])[0]
            i += self._number_width
            text_head_size = unpack(byte_format, key_block_info[i:i+byte_width])[0]
            i += byte_width
            if self._encoding != 'UTF-16':
                i += text_head_size + text_term
            else:
                i += (text_head_size + text_term) * 2
            text_tail_size = unpack(byte_format, key_block_info[i:i+byte_width])[0]
            i += byte_width
            if self._encoding != 'UTF-16':
                i += text_tail_size + text_term
            else:
                i += (text_tail_size + text_term) * 2
            key_block_compressed_size = unpack(self._number_format, key_block_info[i:i+self._number_width])[0]
            i += self._number_width
            key_block_decompressed_size = unpack(self._number_format, key_block_info[i:i+self._number_width])[0]
            i += self._number_width
            key_block_info_list += [(key_block_compressed_size, key_block_decompressed_size)]
        return key_block_info_list

    def _decode_key_block(self, key_block_compressed, key_block_info_list):
        key_list = []
        i = 0
        for compressed_size, decompressed_size in key_block_info_list:
            start = i
            end = i + compressed_size
            key_block_type = key_block_compressed[start:start+4]
            adler32 = unpack('>I', key_block_compressed[start+4:start+8])[0]
            if key_block_type == b'\x00\x00\x00\x00':
                key_block = key_block_compressed[start+8:end]
            elif key_block_type == b'\x01\x00\x00\x00':
                if lzo is None:
                    print("LZO compression is not supported")
                    break
                header = b'\xf0' + pack('>I', decompressed_size)
                key_block = lzo.decompress(header + key_block_compressed[start+8:end])
            elif key_block_type == b'\x02\x00\x00\x00':
                key_block = zlib.decompress(key_block_compressed[start+8:end])
            key_list += self._split_key_block(key_block)
            assert(adler32 == zlib.adler32(key_block) & 0xffffffff)
            i += compressed_size
        return key_list

    def _split_key_block(self, key_block):
        key_list = []
        key_start_index = 0
        while key_start_index < len(key_block):
            key_id = unpack(self._number_format, key_block[key_start_index:key_start_index+self._number_width])[0]
            if self._encoding == 'UTF-16':
                delimiter = b'\x00\x00'
                width = 2
            else:
                delimiter = b'\x00'
                width = 1
            i = key_start_index + self._number_width
            while i < len(key_block):
                if key_block[i:i+width] == delimiter:
                    key_end_index = i
                    break
                i += width
            key_text = key_block[key_start_index+self._number_width:key_end_index]\
                .decode(self._encoding, errors='ignore').encode('utf-8').strip()
            key_start_index = key_end_index + width
            key_list += [(key_id, key_text)]
        return key_list

    def _read_header(self):
        f = open(self._fname, 'rb')
        header_bytes_size = unpack('>I', f.read(4))[0]
        header_bytes = f.read(header_bytes_size)
        adler32 = unpack('<I', f.read(4))[0]
        assert(adler32 == zlib.adler32(header_bytes) & 0xffffffff)
        self._key_block_offset = f.tell()
        f.close()
        header_text = header_bytes[:-2].decode('utf-16').encode('utf-8')
        header_tag = self._parse_header(header_text)
        if not self._encoding:
            encoding = header_tag[b'Encoding']
            if sys.hexversion >= 0x03000000:
                encoding = encoding.decode('utf-8')
            if encoding in ['GBK', 'GB2312']:
                encoding = 'GB18030'
            self._encoding = encoding
        if b'Encrypted' not in header_tag or header_tag[b'Encrypted'] == b'No':
            self._encrypt = 0
        elif header_tag[b'Encrypted'] == b'Yes':
            self._encrypt = 1
        else:
            self._encrypt = int(header_tag[b'Encrypted'])
        self._stylesheet = {}
        if header_tag.get('StyleSheet'):
            lines = header_tag['StyleSheet'].splitlines()
            for i in range(0, len(lines), 3):
                self._stylesheet[lines[i]] = (lines[i+1], lines[i+2])
        self._version = float(header_tag[b'GeneratedByEngineVersion'])
        if self._version < 2.0:
            self._number_width = 4
            self._number_format = '>I'
        else:
            self._number_width = 8
            self._number_format = '>Q'
        return header_tag

    def _read_keys(self):
        f = open(self._fname, 'rb')
        f.seek(self._key_block_offset)
        if self._version >= 2.0:
            num_bytes = 8 * 5
        else:
            num_bytes = 4 * 4
        block = f.read(num_bytes)
        if self._encrypt & 1:
            if self._passcode is None:
                raise RuntimeError('user identification is needed to read encrypted file')
            regcode, userid = self._passcode
            if isinstance(userid, unicode):
                userid = userid.encode('utf8')
            if self.header[b'RegisterBy'] == b'EMail':
                encrypted_key = _decrypt_regcode_by_email(regcode, userid)
            else:
                encrypted_key = _decrypt_regcode_by_deviceid(regcode, userid)
            block = _salsa_decrypt(block, encrypted_key)
        from io import BytesIO
        sf = BytesIO(block)
        num_key_blocks = self._read_number(sf)
        self._num_entries = self._read_number(sf)
        if self._version >= 2.0:
            key_block_info_decomp_size = self._read_number(sf)
        key_block_info_size = self._read_number(sf)
        key_block_size = self._read_number(sf)
        if self._version >= 2.0:
            adler32 = unpack('>I', f.read(4))[0]
            assert(adler32 == (zlib.adler32(block) & 0xffffffff))
        key_block_info = f.read(key_block_info_size)
        key_block_info_list = self._decode_key_block_info(key_block_info)
        assert(num_key_blocks == len(key_block_info_list))
        key_block_compressed = f.read(key_block_size)
        key_list = self._decode_key_block(key_block_compressed, key_block_info_list)
        self._record_block_offset = f.tell()
        f.close()
        return key_list

    def _read_keys_brutal(self):
        f = open(self._fname, 'rb')
        f.seek(self._key_block_offset)
        if self._version >= 2.0:
            num_bytes = 8 * 5 + 4
            key_block_type = b'\x02\x00\x00\x00'
        else:
            num_bytes = 4 * 4
            key_block_type = b'\x01\x00\x00\x00'
        block = f.read(num_bytes)
        key_block_info = f.read(8)
        if self._version >= 2.0:
            assert key_block_info[:4] == b'\x02\x00\x00\x00'
        while True:
            fpos = f.tell()
            t = f.read(1024)
            index = t.find(key_block_type)
            if index != -1:
                key_block_info += t[:index]
                f.seek(fpos + index)
                break
            else:
                key_block_info += t
        key_block_info_list = self._decode_key_block_info(key_block_info)
        key_block_size = sum(list(zip(*key_block_info_list))[0])
        key_block_compressed = f.read(key_block_size)
        key_list = self._decode_key_block(key_block_compressed, key_block_info_list)
        self._record_block_offset = f.tell()
        f.close()
        self._num_entries = len(key_list)
        return key_list

class MDD(MDict):
    """
    MDict 资源文件 (*.MDD) 读取器。
    """
    def __init__(self, fname, passcode=None):
        MDict.__init__(self, fname, encoding='UTF-16', passcode=passcode)

    def items(self):
        """生成 (filename, content) 的元组。"""
        return self._decode_record_block()

    def _decode_record_block(self):
        f = open(self._fname, 'rb')
        f.seek(self._record_block_offset)
        num_record_blocks = self._read_number(f)
        num_entries = self._read_number(f)
        assert(num_entries == self._num_entries)
        record_block_info_size = self._read_number(f)
        record_block_size = self._read_number(f)
        record_block_info_list = []
        size_counter = 0
        for i in range(num_record_blocks):
            compressed_size = self._read_number(f)
            decompressed_size = self._read_number(f)
            record_block_info_list += [(compressed_size, decompressed_size)]
            size_counter += self._number_width * 2
        assert(size_counter == record_block_info_size)
        offset = 0
        i = 0
        size_counter = 0
        for compressed_size, decompressed_size in record_block_info_list:
            record_block_compressed = f.read(compressed_size)
            record_block_type = record_block_compressed[:4]
            adler32 = unpack('>I', record_block_compressed[4:8])[0]
            if record_block_type == b'\x00\x00\x00\x00':
                record_block = record_block_compressed[8:]
            elif record_block_type == b'\x01\x00\x00\x00':
                if lzo is None:
                    print("LZO compression is not supported")
                    break
                header = b'\xf0' + pack('>I', decompressed_size)
                record_block = lzo.decompress(header + record_block_compressed[8:])
            elif record_block_type == b'\x02\x00\x00\x00':
                record_block = zlib.decompress(record_block_compressed[8:])
            assert(adler32 == zlib.adler32(record_block) & 0xffffffff)
            assert(len(record_block) == decompressed_size)
            while i < len(self._key_list):
                record_start, key_text = self._key_list[i]
                if record_start - offset >= len(record_block):
                    break
                if i < len(self._key_list)-1:
                    record_end = self._key_list[i+1][0]
                else:
                    record_end = len(record_block) + offset
                i += 1
                data = record_block[record_start-offset:record_end-offset]
                yield key_text, data
            offset += len(record_block)
            size_counter += compressed_size
        assert(size_counter == record_block_size)
        f.close()

class MDX(MDict):
    """
    MDict 字典文件 (*.mdx) 读取器。
    """
    def __init__(self, fname, encoding='', substyle=False, passcode=None):
        MDict.__init__(self, fname, encoding, passcode)
        self._substyle = substyle

    def items(self):
        """生成 (key, value) 的元组。"""
        return self._decode_record_block()

    def _substitute_stylesheet(self, txt):
        txt_list = re.split('`\d+`', txt)
        txt_tag = re.findall('`\d+`', txt)
        txt_styled = txt_list[0]
        for j, p in enumerate(txt_list[1:]):
            style = self._stylesheet[txt_tag[j][1:-1]]
            if p and p[-1] == '\n':
                txt_styled = txt_styled + style[0] + p.rstrip() + style[1] + '\r\n'
            else:
                txt_styled = txt_styled + style[0] + p + style[1]
        return txt_styled

    def _decode_record_block(self):
        f = open(self._fname, 'rb')
        f.seek(self._record_block_offset)
        num_record_blocks = self._read_number(f)
        num_entries = self._read_number(f)
        assert(num_entries == self._num_entries)
        record_block_info_size = self._read_number(f)
        record_block_size = self._read_number(f)
        record_block_info_list = []
        size_counter = 0
        for i in range(num_record_blocks):
            compressed_size = self._read_number(f)
            decompressed_size = self._read_number(f)
            record_block_info_list += [(compressed_size, decompressed_size)]
            size_counter += self._number_width * 2
        assert(size_counter == record_block_info_size)
        offset = 0
        i = 0
        size_counter = 0
        for compressed_size, decompressed_size in record_block_info_list:
            record_block_compressed = f.read(compressed_size)
            record_block_type = record_block_compressed[:4]
            adler32 = unpack('>I', record_block_compressed[4:8])[0]
            if record_block_type == b'\x00\x00\x00\x00':
                record_block = record_block_compressed[8:]
            elif record_block_type == b'\x01\x00\x00\x00':
                if lzo is None:
                    print("LZO compression is not supported")
                    break
                header = b'\xf0' + pack('>I', decompressed_size)
                record_block = lzo.decompress(header + record_block_compressed[8:])
            elif record_block_type == b'\x02\x00\x00\x00':
                record_block = zlib.decompress(record_block_compressed[8:])
            assert(adler32 == zlib.adler32(record_block) & 0xffffffff)
            assert(len(record_block) == decompressed_size)
            while i < len(self._key_list):
                record_start, key_text = self._key_list[i]
                if record_start - offset >= len(record_block):
                    break
                if i < len(self._key_list)-1:
                    record_end = self._key_list[i+1][0]
                else:
                    record_end = len(record_block) + offset
                i += 1
                record = record_block[record_start-offset:record_end-offset]
                record = record.decode(self._encoding, errors='ignore').strip(u'\x00').encode('utf-8')
                if self._substyle and self._stylesheet:
                    record = self._substitute_stylesheet(record)
                yield key_text, record
            offset += len(record_block)
            size_counter += compressed_size
        assert(size_counter == record_block_size)
        f.close()

# =================== 主程序 ==================
import os
import os.path
import argparse
import codecs
import tkinter
from tkinter import filedialog as tkFileDialog

def passcode(s):
    try:
        regcode, userid = s.split(',')
    except Exception:
        raise argparse.ArgumentTypeError("Passcode 格式必须为 regcode,userid")
    try:
        regcode = codecs.decode(regcode, 'hex')
    except Exception:
        raise argparse.ArgumentTypeError("regcode 必须是32字节的十六进制字符串")
    return regcode, userid

parser = argparse.ArgumentParser(description="合并后的 MDX/MDD 读取器，并支持查词测试")
parser.add_argument('-x', '--extract', action="store_true",
                    help='提取 mdx 为源格式，并从 mdd 中提取文件')
parser.add_argument('-s', '--substyle', action="store_true",
                    help='替换样式定义（如果存在）')
parser.add_argument('-d', '--datafolder', default="data",
                    help='提取 mdd 数据文件存放的文件夹')
parser.add_argument('-e', '--encoding', default="",
                    help='指定编码格式')
parser.add_argument('-p', '--passcode', default=None, type=passcode,
                    help='passcode 格式为 regcode,userid')
parser.add_argument('-w', '--word', default='', help='查词，输入要查询的词')
parser.add_argument("filename", nargs='?', help="mdx 文件名")
args = parser.parse_args()

if not args.filename:
    root = tkinter.Tk()
    root.withdraw()
    args.filename = tkFileDialog.askopenfilename(parent=root)
    args.extract = True

if not os.path.exists(args.filename):
    print("请指定一个有效的 MDX/MDD 文件")
    sys.exit(1)

base, ext = os.path.splitext(args.filename)

mdx = None
if ext.lower() == os.path.extsep + 'mdx':
    mdx = MDX(args.filename, args.encoding, args.substyle, args.passcode)
    print('======== {} ========'.format(args.filename))
    print('  词条数量 : {}'.format(len(mdx)))
    for key, value in mdx.header.items():
        print('  {} : {}'.format(key, value))
else:
    print("当前只支持 mdx 文件")
    sys.exit(1)

# 如果指定了查词，则在字典中搜索该词（不区分大小写）
if args.word:
    found = False
    for key, value in mdx.items():
        # 将 key 转换为字符串
        key_str = key.decode('utf-8', errors='ignore') if isinstance(key, bytes) else key
        if key_str.lower() == args.word.lower():
            print("查词 '{}' 的结果:".format(args.word))
            print(value.decode('utf-8', errors='ignore') if isinstance(value, bytes) else value)
            found = True
            break
    if not found:
        print("未找到词条 '{}'".format(args.word))

if args.extract:
    if mdx:
        output_fname = base + os.path.extsep + 'txt'
        with open(output_fname, 'wb') as tf:
            for key, value in mdx.items():
                tf.write(key)
                tf.write(b'\r\n')
                tf.write(value)
                if not value.endswith(b'\n'):
                    tf.write(b'\r\n')
                tf.write(b'</>\r\n')
        if mdx.header.get('StyleSheet'):
            style_fname = base + '_style' + os.path.extsep + 'txt'
            with open(style_fname, 'wb') as sf:
                sf.write(b'\r\n'.join(mdx.header['StyleSheet'].splitlines()))
    mdd_filename = base + os.path.extsep + 'mdd'
    if os.path.exists(mdd_filename):
        datafolder = os.path.join(os.path.dirname(args.filename), args.datafolder)
        if not os.path.exists(datafolder):
            os.makedirs(datafolder)
        mdd = MDD(mdd_filename, args.passcode)
        print('======== {} ========'.format(mdd_filename))
        print('  词条数量 : {}'.format(len(mdd)))
        for key, value in mdd.header.items():
            print('  {} : {}'.format(key, value))
        for key, value in mdd.items():
            fname = key.decode('utf-8').replace('\\', os.path.sep)
            dfname = os.path.join(datafolder, fname)
            if not os.path.exists(os.path.dirname(dfname)):
                os.makedirs(os.path.dirname(dfname))
            with open(dfname, 'wb') as df:
                df.write(value)