#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# exodia_mitm.py — MITM 6–6 tối ưu + kiểm tra public_key

import sys, os, re, json, socket, hashlib, itertools

# ===== secp256k1 =====
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G  = (Gx, Gy)

def modinv(a, n): return pow(a, -1, n)

def point_add(Pt, Qt):
    if Pt is None: return Qt
    if Qt is None: return Pt
    x1,y1 = Pt; x2,y2 = Qt
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if Pt == Qt:
        s = (3*x1*x1) * modinv((2*y1) % P, P) % P
    else:
        s = ((y2 - y1) * modinv((x2 - x1) % P, P)) % P
    x3 = (s*s - x1 - x2) % P
    y3 = (s*(x1 - x3) - y1) % P
    return (x3, y3)

def point_neg(Pt):
    if Pt is None: return None
    x,y = Pt; return (x, (-y) % P)

def scalar_mult(k, Pt=G):
    if k % N == 0 or Pt is None: return None
    if k < 0: return scalar_mult(-k, (Pt[0], (-Pt[1]) % P))
    res = None; add = Pt
    while k:
        if k & 1: res = point_add(res, add)
        add = point_add(add, add)
        k >>= 1
    return res

def pub_compressed_from_d(d: int) -> str:
    Px, Py = scalar_mult(d, G)
    return ("%02x" % (0x02 if (Py % 2 == 0) else 0x03)) + Px.to_bytes(32,'big').hex()

def sqrt_mod_p(a):  # P % 4 == 3
    return pow(a, (P+1)//4, P)

def lift_x_to_points(r_int):
    out = []
    for Rx in (r_int, r_int + N):
        if Rx >= P: continue
        rhs = (pow(Rx,3,P) + 7) % P
        y = sqrt_mod_p(rhs)
        if (y*y) % P == rhs:
            out.append((Rx, y))
            out.append((Rx, (-y) % P))
    return out

def key_compress(Pt):
    if Pt is None: return b"\x00"*33
    x,y = Pt
    return bytes([0x02 if (y & 1) == 0 else 0x03]) + x.to_bytes(32, 'big')

# ===== socket I/O =====
def sendline(f, s): f.write(s+"\n"); f.flush()
def recv_until_prompt(f, timeout=12.0):
    f.sock.settimeout(timeout)
    out=[]
    while True:
        line=f.readline()
        if not line: break
        out.append(line)
        if line.strip().endswith(">"): break
    return "".join(out)

def grab_json(buf):
    m = re.search(r"\[.*\]", buf, re.S)
    if not m: raise RuntimeError("Không thấy JSON mảng")
    return json.loads(m.group(0))

def grab_pub_hex(buf):
    m = re.search(r"public_key:\s*([0-9a-fA-F]+)", buf)
    return m.group(1).lower() if m else None

# ===== bảng 2×8-bit cho mỗi vị trí =====
def precompute_tables():
    # Q_j = (2^(16j) mod N)*G, C_j = 256*Q_j
    Q = [scalar_mult(pow(2, 16*j, N), G) for j in range(12)]
    T0, T1 = [], []
    for j in range(12):
        Bj = Q[j]
        Cj = Bj
        for _ in range(8):  # 2^8 * Bj
            Cj = point_add(Cj, Cj)
        row0 = [None]*256
        row1 = [None]*256
        row0[0] = None; row1[0] = None
        row0[1] = Bj;   row1[1] = Cj
        for b in range(2,256):
            row0[b] = point_add(row0[b-1], Bj)
            row1[b] = point_add(row1[b-1], Cj)
        T0.append(row0); T1.append(row1)
    return T0, T1

def contrib(T0, T1, pos_j, word16):
    lo = word16 & 0xFF
    hi = (word16 >> 8) & 0xFF
    a = T0[pos_j][lo]
    b = T1[pos_j][hi]
    return a if b is None else (b if a is None else point_add(a,b))

# ===== build HIGH map =====
def build_high_map(words16, T0, T1):
    pos_hi = list(range(6,12))
    idxs = list(range(12))
    high_map = {}
    for comb in itertools.combinations(idxs, 6):
        mat = [[None]*6 for _ in range(6)]
        for k,j in enumerate(pos_hi):
            for t in range(6):
                mat[k][t] = contrib(T0, T1, j, words16[comb[t]])
        for perm in itertools.permutations(range(6)):
            S = None
            for k in range(6):
                S = mat[k][perm[k]] if S is None else point_add(S, mat[k][perm[k]])
            key = key_compress(S)
            high_map.setdefault(key, tuple(comb[p] for p in perm))
    return high_map

# ===== scan LOW and match =====
def find_k_with_mitm(words16, r_int, T0, T1, high_map):
    pos_lo = list(range(0,6))
    Rcands = lift_x_to_points(r_int % N)
    if not Rcands: return None, None
    idxs = list(range(12))
    for comb in itertools.combinations(idxs, 6):
        mat = [[None]*6 for _ in range(6)]
        for k,j in enumerate(pos_lo):
            for t in range(6):
                mat[k][t] = contrib(T0, T1, j, words16[comb[t]])
        for perm in itertools.permutations(range(6)):
            Slo = None
            for k in range(6):
                Slo = mat[k][perm[k]] if Slo is None else point_add(Slo, mat[k][perm[k]])
            Sneg = point_neg(Slo)
            for R in Rcands:
                need = point_add(R, Sneg)
                key = key_compress(need)
                hi_perm_idx = high_map.get(key)
                if hi_perm_idx is None:
                    continue
                if set(hi_perm_idx) & set(comb):  # disjointness
                    continue
                by_pos = [None]*12
                for k,j in enumerate(pos_lo):      by_pos[j] = comb[perm[k]]
                for k,j in enumerate(range(6,12)): by_pos[j] = hi_perm_idx[k]
                # k_bytes: 8 zero + words16[J=11..0] as big-endian 2B
                tail = b''.join(int(words16[by_pos[j]]).to_bytes(2,'big') for j in range(11,-1,-1))
                k_bytes = b'\x00'*8 + tail
                k = int.from_bytes(k_bytes, 'big') % N
                return k, by_pos
    return None, None

def xor_split_5(d_bytes: bytes):
    a = os.urandom(32)
    b = os.urandom(32)
    c = os.urandom(32)
    d4 = os.urandom(32)
    e = bytes(x ^ y ^ z ^ w ^ t for (x,y,z,w,t) in zip(d_bytes, a, b, c, d4))  # a^b^c^d4^e = d
    return [a, b, c, d4, e]

def main():
    host = "103.197.184.48"; port = 41337
    if len(sys.argv) >= 2: host = sys.argv[1]
    if len(sys.argv) >= 3: port = int(sys.argv[2])

    s = socket.create_connection((host, port), timeout=12.0)
    f = s.makefile('rw', buffering=1, newline='\n'); f.sock = s
    recv_until_prompt(f)

    # public_key (để kiểm tra d)
    sendline(f, "public_key")
    pub_hex = grab_pub_hex(recv_until_prompt(f)) or ""

    # choices -> 12 id
    sendline(f, "choices")
    choices = grab_json(recv_until_prompt(f))
    ids = [int(x["id"]) for x in choices]
    words16 = [x & 0xFFFF for x in ids]

    # vaults -> signatures
    sendline(f, "vaults")
    vaults = grab_json(recv_until_prompt(f))

    # precompute tables and high_map
    T0, T1 = precompute_tables()
    high_map = build_high_map(words16, T0, T1)

    for v in vaults:
        vid = v["id"]
        sig = bytes.fromhex(v["signature"])
        r = int.from_bytes(sig[:32], 'big') % N
        s_int = int.from_bytes(sig[32:], 'big') % N
        z = int.from_bytes(hashlib.sha256(vid.encode()).digest(), 'big') % N

        k, order = find_k_with_mitm(words16, r, T0, T1, high_map)
        if k is None:
            continue

        d = ((s_int * k - z) * modinv(r, N)) % N

        # Kiểm tra public key cho chắc
        if pub_hex:
            if pub_compressed_from_d(d).lower() != pub_hex.lower():
                continue  # sai k → thử vault khác

        parts = xor_split_5(d.to_bytes(32,'big'))
        payload = " ".join(p.hex() for p in parts)
        sendline(f, "unlock_exodia " + payload)
        print(recv_until_prompt(f))
        f.close(); s.close()
        return

    print("Không tìm được k/d khớp public_key.")
    f.close(); s.close()

if __name__ == "__main__":
    main()
