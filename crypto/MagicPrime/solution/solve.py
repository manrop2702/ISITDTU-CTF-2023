from sage.all import Zmod, prod, randint, ZZ, PolynomialRing, block_matrix, matrix, GF, factor, discrete_log, crt
from gmpy2 import is_prime
from fpylll import IntegerMatrix, BKZ
from fpylll.fplll.gso import MatGSO
from fpylll.fplll.enumeration import Enumeration, EvaluatorStrategy
from fpylll.util import set_threads
from tqdm import tqdm
from hashlib import sha256

nbits = 160
avg = 13
factor_cnt = 37
sol_cnt = 100000
mod = 2**nbits
Zn = Zmod(mod)


def check_vector(args):
    (out, A, bs, target, n2) = args
    v = IntegerMatrix.from_iterable(1, A.nrows, map(ZZ, out[1]))
    # print(v)
    sv = v * A
    if sv[0, 0] != 0 or (sv[0, -1] not in (-1, 1)) or any(avg < abs(sv[0, i+1]) for i in range(len(bs))):
        return
    neg = sv[0, -1]
    sol = [avg + neg * sv[0, i + 1] for i in range(len(bs))]
    pw = []
    for b, cnt in zip(bs, sol):
        pw += [b]*cnt
    pw = 2**n2 * prod(pw) + 1
    # assert 2**n2*target + 1 == pw % mod
    # print(f"Number = {pw}, Bits length: {pw.bit_length()} Is Prime: {is_prime(pw)}")
    if pw.bit_length() >= 4096 and is_prime(pw):
        # print(f"Found a valid vector: {sv} for: ")
        # print(A)
        # print(f"SolutionL: {sol}")
        return pw


def try_log(a, b):
    try:
        return Zn(a).log(Zn(b))
    except Exception:
        return None


def ssproduct_solve(target, primes, k2):
    while True:
        g = Zn(randint(0, mod-1) | 1)
        if not (xtarget := try_log(target, g)):
            continue
        es = []
        ps = []
        for p in primes:
            tmp = try_log(p, g)
            if tmp is None:
                continue
            es.append(tmp)
            ps.append(p)
            if len(ps) > factor_cnt:
                break
        else:
            continue
        break
    phi = g.multiplicative_order()
    ns = PolynomialRing(ZZ, "n", len(ps)).gens()
    L = block_matrix(ZZ, [
        [phi, 0],
        [matrix(sum([(n + avg)*x for n, x in zip(ns, es)]).coefficients()).T, 1]
    ])
    L[-1, 0] -= xtarget
    size = int(L.nrows())
    A = IntegerMatrix.from_matrix(L)
    A = BKZ.reduction(A, BKZ.Param(50))
    MG = MatGSO(A)
    MG.update_gso()
    # print(MG.babai([0]*(factor_cnt+1) + [1]))
    enum = Enumeration(
        MG, sol_cnt, strategy=EvaluatorStrategy.BEST_N_SOLUTIONS)
    for out in enum.enumerate(0, size, factor_cnt*avg**2 + 1, 0):
        yield (out, A, ps, target, k2)


def gen_PoW(prefix):
    i = 0
    while True:
        yield prefix+str(i).encode()
        i += 1


def timeout_handler(sig, frame):
    print('Time out!')
    exit(0)


if __name__ == "__main__":
    import os
    import signal
    from multiprocessing import Pool
    from pwn import remote, process
    from Crypto.Util.number import sieve_base
    set_threads(os.cpu_count()*2)
    primes = sieve_base[30:]
    with Pool(os.cpu_count()) as executor:
        io = process(["python", "../src/server.py"])
        # io = remote("localhost", 5001)
        # io = remote("34.124.255.88", 5001)
        io.recvuntil(b"sha256(\"")
        prefix = io.recv(16)
        io.recvuntil(b"Suffix: ")
        for buf in gen_PoW(prefix):
            if sha256(buf).hexdigest().startswith("000000"):
                io.sendline(buf[16:])
                break
        signal.signal(signal.SIGALRM, timeout_handler)
        salt = int(io.recvline(0).split(b" = ")[-1])
        signal.alarm(30)
        n2 = 1
        lsb = salt >> 1
        while lsb % 2 == 0:
            lsb >>= 1
            n2 += 1
        for cnt in range(20):
            print("Number of tries:", cnt+1)
            for P in tqdm(executor.map(check_vector, ssproduct_solve(lsb, primes, n2))):
                if P is not None:
                    break
            else:
                continue
            print(f"Prime = {P}, Bits length: {P.bit_length()}")
            # print(factor(P - 1))
            break
        else:
            exit(1)
        io.sendlineafter(b": ", str(P).encode())
        F = GF(P)
        g = F(io.recvline(0).split(b" = ")[-1])
        H = F(io.recvline(0).split(b" = ")[-1])
        xs = []
        ms = []
        phi = P-1
        for p, e in factor(phi):
            while e:
                if g**(phi//p) != 1:
                    break
                e -= 1
                phi /= p
        # assert g**phi == 1
        for p, e in tqdm(factor(phi)):
            m = p**e
            tmp = phi // m
            xs.append(discrete_log(H**tmp, g**tmp, ord=m))
            ms.append(m)
        x = crt(xs, ms)
        # print(f"{x = }")
        io.sendlineafter(b": ", str(x).encode())
        print(io.recvline().decode())
        # io.interactive()
