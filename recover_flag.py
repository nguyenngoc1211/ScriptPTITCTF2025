#!/usr/bin/env python3
alphabet = b"QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm0123456789-_"
byte_2220 = bytes.fromhex(
    "87a45521ac4b57ae13ab5d975cfdf0b5ca5d22cfe7e03f98495806af879050bce3a930fce0b38fae4c04563976c03993dc0821f7c2e256fcfe16de43"
)[:60]
aN0Dbg_str = b"n0_dbg^_^"

def init_state():
    v = 0x811C9DC5
    for ch in aN0Dbg_str:
        v = ((v ^ ch) * 0x1000193) & 0xFFFFFFFF
    return (v ^ 0x9E377985) & 0xFFFFFFFF

def prng_step(v):
    m = 0xFFFFFFFF
    v &= m
    a = (v ^ ((v << 13) & m)) & m
    t = (a >> 17) & m
    part = (t ^ v ^ ((v << 13) & m)) & m
    return (v ^ t ^ ((v << 13) & m) ^ ((32 * part) & m)) & m

def idx_aN0Dbg(j):
    mul = 0xE38E38E38E38E38F
    prod = (j * mul) & ((1 << 128) - 1)
    hi = (prod >> 64) & ((1 << 64) - 1)
    rdx = hi & ~7
    rax = hi >> 3
    val = (rdx + rax) & 0xFFFFFFFFFFFFFFFF
    idx = (j - val) & 0xFFFFFFFFFFFFFFFF
    return idx

def build_post():
    v = init_state()
    out = bytearray()
    for j in range(60):
        v = prng_step(v)
        idx = idx_aN0Dbg(j)
        addv = aN0Dbg_str[idx] if idx < len(aN0Dbg_str) else 0
        exp = (v + addv) & 0xFF
        out.append(byte_2220[j] ^ exp)
    return bytes(out)

def invert_perm(post):
    pre = bytearray(60)
    ecx = 1
    for k in range(15):
        x = ecx & 3
        off = 4*k
        for i in range(4):
            pre[off + ((x + i) & 3)] = post[off + i]
        ecx += 3
    return bytes(pre)

def b64_custom_decode(data):
    inv = {alphabet[i]: i for i in range(64)}
    out = bytearray()
    for i in range(0, 60, 4):
        v0, v1, v2, v3 = (inv.get(c,0) for c in data[i:i+4])
        val = (v0<<18) | (v1<<12) | (v2<<6) | v3
        out += bytes([(val>>16)&0xFF, (val>>8)&0xFF, val&0xFF])
    return bytes(out)

if __name__ == "__main__":
    post = build_post()
    pre = invert_perm(post)
    decoded = b64_custom_decode(pre)
    flag = decoded[:43].decode()
    print(flag)
