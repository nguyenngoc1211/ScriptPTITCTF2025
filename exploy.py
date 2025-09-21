#!/usr/bin/env python3
# exploit.py — full, debug-friendly
import sys, socket, hashlib, time, re, random

# constants
BITS = 20
MOD = 1 << BITS
ROUND_CONST = 0x9E377
TILE_NORMAL, TILE_BOOST, TILE_MUD, TILE_OIL = ".", "B", "M", "O"

def sha1_hex(x): return hashlib.sha1(str(x).encode()).hexdigest()
def ticket_of(s): return (s*31337+1337)&0xFFFF
def seed_for_round(secret, r): return (secret ^ ((r*ROUND_CONST)%MOD)) % MOD

def derive_int(*parts, bits=64):
    h = hashlib.sha1()
    for p in parts:
        h.update(str(p).encode()); h.update(b"|")
    return int.from_bytes(h.digest(), "big") & ((1<<bits)-1)

# Track + Engine (copied from challenge)
class FancyTrack:
    def __init__(self, seed, lane, length):
        rng = random.Random(derive_int("track", seed, lane, length, bits=64))
        self.tiles = []
        for _ in range(length):
            r = rng.random()
            self.tiles.append(TILE_BOOST if r<0.06 else TILE_MUD if r<0.11 else TILE_OIL if r<0.16 else TILE_NORMAL)
    def at(self, x, length): return self.tiles[x] if 0 <= x < length else TILE_NORMAL

class DuckEngine:
    def __init__(self, seed, n, length=60):
        self.rng = random.Random(seed)
        self.n, self.length = n, length
        self.x   = [0]*n
        self.cd  = [0]*n
        self.trk = [FancyTrack(seed, i, length) for i in range(n)]
        self.wind_bias = self.rng.random()*0.08
        self.wind_puff = self.rng.random()*0.05
        self.finish_eps = [ (derive_int("finish_eps", seed, i, length, bits=64)/float(1<<64))*1e-6 + i*1e-9 for i in range(n) ]

    def step_once(self):
        prev = self.x[:]
        for i in range(self.n):
            prog = self.x[i]/max(1,self.length)
            step = self.rng.choice([0,1,1,1,2] if prog<0.7 else [0,1,1,1,1,2])
            if self.rng.random() < self.wind_bias: step += 1
            if self.rng.random() < self.wind_puff: step += 1
            if any(px - prev[i] in (1,2) for j,px in enumerate(prev) if j!=i): step += 1
            tentative = min(self.length, self.x[i]+step)
            tile = self.trk[i].at(tentative, self.length)
            slip_p = 0.05 + (0.10 if tile==TILE_OIL else 0.0)
            if tile==TILE_BOOST: step += 1
            elif tile==TILE_MUD: step = max(0, step-1)
            if self.rng.random() < slip_p:
                self.x[i] = max(0, self.x[i]-1)
                if self.cd[i]>0: self.cd[i]-=1
                continue
            if self.cd[i]<=0 and self.rng.random()<0.08:
                step += 2
                self.cd[i] = self.rng.randint(10,16)
            self.x[i] = min(self.length, self.x[i]+step)
            if self.cd[i]>0: self.cd[i]-=1

    def winner_1based_eps(self):
        best_i, best_s = 0, -1e99
        for i in range(self.n):
            s = self.x[i] - (self.length + self.finish_eps[i])
            if s > best_s: best_s, best_i = s, i
        return [best_i+1]

# parsing helpers
def parse_commit(line):
    m = re.search(r"COMMIT:\s*([0-9a-fA-F]{40})", line); return m.group(1).lower() if m else None
def parse_ticket(line):
    m = re.search(r"TICKET:\s*(\d+)", line); return int(m.group(1)) if m else None
def parse_prompt_for_n(line):
    m = re.search(r"1\.\.(\d+)", line); return int(m.group(1)) if m else None

def find_seed_from_commit_ticket(commit, ticket):
    for s in range(1<<BITS):
        if ticket_of(s) != ticket: continue
        if sha1_hex(s) == commit: return s
    return None

def recv_until_patterns(f, patterns, timeout=8.0):
    end = time.time()+timeout
    buf=""
    while time.time()<end:
        line = f.readline()
        if not line: break
        txt=line.decode(errors="ignore")
        buf += txt
        sys.stdout.write(txt); sys.stdout.flush()
        for p in patterns:
            if p in txt:
                return buf
    return buf

def exploit(host, port):
    s = socket.create_connection((host,int(port)), timeout=15)
    f = s.makefile("rwb", buffering=0)

    commit=None; ticket=None
    # read until commit+ticket
    for _ in range(400):
        line = f.readline()
        if not line: break
        txt=line.decode(errors="ignore")
        sys.stdout.write(txt); sys.stdout.flush()
        commit = commit or parse_commit(txt)
        ticket = ticket or parse_ticket(txt)
        if commit and ticket: break

    if not (commit and ticket):
        print("No commit/ticket"); return
    print(f"[+] COMMIT={commit} TICKET={ticket}")

    seed1 = find_seed_from_commit_ticket(commit, ticket)
    if seed1 is None:
        print("Cannot recover seed"); return
    print(f"[+] seed_round1 = {seed1}")
    secret = seed1 ^ ((1*ROUND_CONST)%MOD)
    print(f"[+] secret = {secret}")

    round_idx = 1
    while True:
        buf = recv_until_patterns(f, ["Hãy nhập", "hãy nhập", "Please enter", "nhập chỉ số"], timeout=12.0)
        if not buf:
            break
        # parse n
        n = None
        for L in buf.splitlines()[-12:]:
            n = parse_prompt_for_n(L) or n
        if n is None:
            n = 3 + (round_idx-1)
        seed_r = seed_for_round(secret, round_idx)
        eng = DuckEngine(seed_r, n, length=60)
        while max(eng.x) < eng.length:
            eng.step_once()
        predicted = eng.winner_1based_eps()[0]
        print(f"[+] round={round_idx} seed_r={seed_r} predict={predicted} (n={n})")
        try:
            f.write((str(predicted)+"\n").encode()); f.flush()
        except BrokenPipeError:
            print("[!] BrokenPipe when sending. Server closed.")
            break

        # read until reveal and check
        reveal_seed=None; reveal_winner=None
        for _ in range(300):
            line = f.readline()
            if not line: break
            txt=line.decode(errors="ignore")
            sys.stdout.write(txt); sys.stdout.flush()
            m = re.search(r"REVEAL seed\s*=\s*(\d+)", txt)
            if m: reveal_seed=int(m.group(1))
            m2 = re.search(r"Quán quân: lane #(\d+)", txt)
            if m2: reveal_winner=int(m2.group(1))
            if reveal_seed is not None and reveal_winner is not None:
                break

        print(f"[DBG] server revealed seed={reveal_seed} winner={reveal_winner}")
        if reveal_seed is not None and reveal_seed != seed_r:
            print("[ERR] reveal seed mismatch. Abort."); break
        if reveal_winner is not None and reveal_winner != predicted:
            print("[ERR] prediction mismatch. Stop to inspect logs."); break

        round_idx += 1

    f.close(); s.close()

if __name__=="__main__":
    if len(sys.argv)<3:
        print("Usage: python3 exploit.py HOST PORT"); sys.exit(1)
    exploit(sys.argv[1], sys.argv[2])
