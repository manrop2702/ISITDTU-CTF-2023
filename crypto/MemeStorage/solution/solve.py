from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad
from forbidden_attack import recover_possible_auth_keys, forge_tag, _from_gf2e, _to_gf2e, gf2e
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pwn import remote, process
from hashlib import sha256
import json


# io = process("../src/server.py")
# io = remote("localhost", 5002)
def gen_PoW(prefix):
    i = 0
    while True:
        yield prefix+str(i).encode()
        i += 1
io = remote("34.143.249.126", 5002)
io.recvuntil(b"sha256(\"")
prefix = io.recv(16)
io.recvuntil(b"Suffix: ")
for buf in gen_PoW(prefix):
    if sha256(buf).hexdigest().startswith("000000"):
        io.sendline(buf[16:])
        break


def encrypt(name, nonce):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b": ", json.dumps({"username": name, "nonce": nonce.hex()}).encode())
    cookie = json.loads(io.recvline(0))["cookie"]
    nonce, ct, tag = [bytes.fromhex(x) for x in cookie.split(".")]
    return nonce, ct, tag


def xor(a, b):
    c = []
    for i, j in zip(a, b):
        c.append(i ^ j)
    return bytes(c)


def forge_ecb_ciphertext(_msg, chosen_plaintext, auth_key):
    assert len(_msg) < 16
    msg = bytearray(pad(_msg, 16))
    msg[-1] -= 1
    ntarget = _to_gf2e(bytes_to_long(msg))
    xx = gf2e["xx"].gens()[0]
    f = ((xx*auth_key) + _to_gf2e(int.from_bytes(b'\x00' *
         8 + long_to_bytes(8 * 16, 8), "big"))) * auth_key - ntarget
    sus_nonce = int(_from_gf2e(f.roots()[0][0])).to_bytes(16, 'big')
    (_, ct, _) = encrypt('Bob', sus_nonce)
    stream = xor(ct, chosen_plaintext)
    return stream[:16].hex()


nonce = b'a' * 16
n0, ct0, t0 = encrypt('test', nonce)

m1 = b'{"username": "Bob", "admin_access": false}'
m2 = b'{"username": "Nam", "admin_access": false}'
n1, ct1, t1 = encrypt('Bob', nonce)
n2, ct2, t2 = encrypt('Nam', nonce)
assert xor(m1, ct1) == xor(m2, ct2)
for hash_key in recover_possible_auth_keys(b'', ct1, t1, b'', ct2, t2):
    if forge_tag(hash_key, b'', ct1, t1, b'', ct0) == t0:
        h = hash_key
        break

flag_name_enc = forge_ecb_ciphertext(b'd4rkbruh', m1, h)
print("Encrypted flag's name =", flag_name_enc)


stream = xor(m1, ct1)
msg = b'{"username": "Bob", "admin_access": true}'
ct = xor(msg, stream)
tag = forge_tag(h, b'', ct1, t1, b'', ct)
payload = {
    "cookie": nonce.hex() + "." + ct.hex() + "." + tag.hex(), 
    "id": flag_name_enc
}
print("Forged payload =", payload)
io.sendlineafter(b"> ", b"3")
io.sendlineafter(b": ", json.dumps(payload).encode())
io.interactive()
