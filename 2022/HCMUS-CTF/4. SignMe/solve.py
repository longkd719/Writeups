import base64
from pwn import remote
from Crypto.Util.number import *
from hashlib import sha256

r = remote("103.245.250.31",31850)
r.recvuntil(b"Select an option: ")
r.sendline(b'0')
r.recvuntil(b"g = ")
g = int(r.recvline().strip())
r.recvuntil(b"p = ")
p = int(r.recvline().strip())
print(g,p)

r.recvuntil(b"Select an option: ")
r.sendline(b"1")
msg = base64.b64encode(b"\x00"*32)
r.sendline(msg)
r.recvuntil(b"Signature (r, s):  (")
r1 = int(r.recvuntil(b", ", drop=True))
s1 = int(r.recvuntil(b")", drop=True))
h1 = bytes_to_long(sha256(msg).digest())
print(r1,s1)
x = ((h1 - s1)*pow(r1,-1,p-1)) % (p-1)
assert (h1 - x*r1) % (p-1) == s1
y = pow(g,x,p)
assert pow(g, h1, p) == (pow(y, r1, p) * pow(r1, s1, p)) % p 
print("TEST DONE")

###
r.recvuntil(b"Select an option: ")
r.sendline(b"3")
r.recvuntil(b"Could you sign this for me:  ")
msg = r.recvline().strip()
_r = pow(g,123123,p)
_h = bytes_to_long(sha256(msg).digest())
_s = ((_h - x * _r) * inverse(123123, p - 1)) % (p - 1)
r.recvuntil(b"Input r: ")
r.sendline(base64.b64encode(long_to_bytes(_r)))
r.recvuntil(b"Input s: ")
r.sendline(base64.b64encode(long_to_bytes(_s)))
print(r.recvline())