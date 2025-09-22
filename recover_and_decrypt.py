#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, base64, binascii
from math import gcd
from typing import List, Tuple

# ---------- Utils ----------
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b//a) * y, y)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Không có nghịch đảo modulo")
    return x % m

def bytes_to_long(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def long_to_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    size = (x.bit_length() + 7) // 8
    return x.to_bytes(size, 'big')

# Miller-Rabin cho số lớn (ngẫu nhiên đủ an toàn thực tế)
import random
def is_probable_prime(n: int, k: int = 16) -> bool:
    if n < 2:
        return False
    # small primes quick check
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 = d * 2^r
    r, d = 0, n-1
    while d % 2 == 0:
        d >>= 1
        r += 1
    # test rounds
    for _ in range(k):
        a = random.randrange(2, n-2)
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        skip = False
        for __ in range(r-1):
            x = pow(x, 2, n)
            if x == n-1:
                skip = True
                break
        if skip:
            continue
        return False
    return True

# ---------- ASN.1 INTEGER scan ----------
def find_asn1_integers(chunk: bytes) -> List[Tuple[int,int,bytes]]:
    """
    Trích các INTEGER trong mẩu DER (có thể không bắt đầu từ đầu sequence).
    Trả về list (pos, length, value_bytes) – value_bytes đã loại header tag/len.
    """
    i = 0
    out = []
    L = len(chunk)
    while i < L:
        if chunk[i] == 0x02:  # INTEGER tag
            if i+1 >= L:
                break
            l1 = chunk[i+1]
            if l1 == 0x81:
                if i+2 >= L: break
                length = chunk[i+2]
                start = i+3
            elif l1 == 0x82:
                if i+3 >= L: break
                length = (chunk[i+2] << 8) | chunk[i+3]
                start = i+4
            elif l1 & 0x80:  # lengths with >2 bytes (rare here)
                nlen = l1 & 0x7F
                if i+1+ nlen >= L: break
                length = 0
                for j in range(nlen):
                    length = (length << 8) | chunk[i+2+j]
                start = i+2+nlen
            else:
                length = l1
                start = i+2

            end = start + length
            if end <= L:
                val = chunk[start:end]
                out.append((i, length, val))
                i = end
            else:
                # truncated at the end of chunk
                # keep truncated info? we just stop
                break
        else:
            i += 1
    return out

def read_partial_der_from_pem(pem_path: str) -> bytes:
    raw = open(pem_path, 'r', encoding='utf-8', errors='ignore').read().strip().splitlines()
    in_key = False
    b64_lines = []
    for line in raw:
        line = line.strip()
        if line.startswith('-----BEGIN RSA PRIVATE KEY'):
            in_key = True
            continue
        if line.startswith('-----END RSA PRIVATE KEY'):
            in_key = False
            continue
        if not in_key:
            continue
        # bỏ những dòng bôi/che
        if '[' in line or 'REDACT' in line or len(line) == 0:
            continue
        # chỉ giữ dòng base64 hợp lệ
        if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in line):
            b64_lines.append(line)
    data_b64 = ''.join(b64_lines)
    if not data_b64:
        raise ValueError("Không thấy dòng base64 thật trong PEM.")
    try:
        return base64.b64decode(data_b64, validate=False)
    except binascii.Error:
        # thử thêm padding
        pad = (-len(data_b64)) % 4
        return base64.b64decode(data_b64 + "="*pad, validate=False)

def recover_key_and_decrypt(pem_path: str, ct_path: str, e: int = 65537, kmax: int = 1000000):
    # 1) lấy mẩu DER còn lại
    part = read_partial_der_from_pem(pem_path)
    print(f"[+] Partial DER bytes: {len(part)}")

    # 2) tìm các INTEGER trong mẩu
    ints = find_asn1_integers(part)
    if len(ints) < 2:
        raise ValueError("Không đủ INTEGER trong mẩu DER để tiếp tục.")

    # 3) heuristic: chọn 2 INTEGER dài nhất ~ q, dp
    ints_sorted = sorted(ints, key=lambda x: x[1], reverse=True)
    big1 = ints_sorted[0]  # (pos, length, val)
    big2 = ints_sorted[1]
    # Lưu ý: thứ tự trong chunk thường là q rồi dp. Nếu đảo, vẫn recovery được – chỉ cần gán đúng.
    # Ta thử cả 2 cách gán.
    candidates = [
        ("q_dp", big1, big2),
        ("q_dp_swapped", big2, big1),
    ]

    # p_tail = bytes trước INTEGER đầu tiên trong chunk
    first_int_pos = min(p for p,_,_ in ints)
    p_tail = part[:first_int_pos]
    print(f"[+] Tail của p (p_tail) bytes: {len(p_tail)}")

    # 4) đọc ciphertext
    ct_raw = open(ct_path,'r',encoding='utf-8',errors='ignore').read().strip()
    # chấp nhận '0x...' hoặc decimal
    c = int(ct_raw, 0)

    for tag, Q, DP in candidates:
        q_bytes = Q[2]
        dp_bytes = DP[2]

        # loại bỏ leading 0 nếu có (ASN.1 INTEGER dương)
        if len(q_bytes) > 0 and q_bytes[0] == 0x00:
            q_bytes = q_bytes[1:]
        if len(dp_bytes) > 0 and dp_bytes[0] == 0x00:
            dp_bytes = dp_bytes[1:]

        q = bytes_to_long(q_bytes)
        dp = bytes_to_long(dp_bytes)
        print(f"[+] Thử mapping {tag}: len(q)={len(q_bytes)} bytes, len(dp)={len(dp_bytes)} bytes")

        # sanity check
        if q % 2 == 0:
            print("    [-] q chẵn? Bỏ mapping này.")
            continue
        if gcd(e, q-1) != 1:
            print("    [-] gcd(e, q-1) != 1? Bỏ mapping này.")
            continue

        # 5) brute-force k để tìm p
        M = e*dp - 1
        # build int của p_tail để khớp đuôi
        tail_len = len(p_tail)
        tail_mask = (1 << (8*tail_len)) - 1 if tail_len > 0 else None
        tail_val  = bytes_to_long(p_tail) if tail_len > 0 else None

        found_p = None
        # đặt bound khởi điểm: nhiều bài k <= e là đủ
        bound = min(kmax, max(4*e, 100000))
        for k in range(1, bound+1):
            if M % k != 0:
                continue
            p_cand = M//k + 1
            if tail_len > 0:
                if (p_cand & tail_mask) != tail_val:
                    continue
            # primality
            if not is_probable_prime(p_cand):
                continue
            found_p = p_cand
            print(f"[+] Tìm được p tại k={k}, bits={found_p.bit_length()}")
            break

        if not found_p:
            print("    [-] Không tìm thấy p với mapping này.")
            continue

        p = found_p
        n = p * q
        phi = (p-1)*(q-1)
        d = modinv(e, phi)
        print(f"[+] n bits={n.bit_length()}  (kỳ vọng 4096 nếu RSA-4096)")
        print(f"[+] Kiểm tra dp: {(d % (p-1)) == dp}")

        # 6) Giải mã
        m = pow(c, d, n)
        m_bytes = long_to_bytes(m)
        try:
            pt = m_bytes.decode('utf-8')
        except UnicodeDecodeError:
            pt = None
        print("\n========== KẾT QUẢ ==========")
        if pt is not None:
            print(pt)
        else:
            print("Hex:", m_bytes.hex())

        # 7) (tuỳ chọn) ghi lại PEM PKCS#1
        # (Đủ dùng giải mã rồi nên có thể bỏ qua. Nếu cần, có thể dùng pyasn1/cryptography để build PEM.)
        return

    raise RuntimeError("Không khôi phục được p. Hãy tăng kmax hoặc kiểm tra lại parsing.")

if __name__ == "__main__":
    pem = sys.argv[1] if len(sys.argv) > 1 else "private.pem"
    ctf = sys.argv[2] if len(sys.argv) > 2 else "ciphertext.txt"
    recover_key_and_decrypt(pem, ctf)
