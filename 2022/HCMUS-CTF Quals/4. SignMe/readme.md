# Sign Me
> Đề bài cho file [chal.py](https://github.com/longkd719/Writeups/blob/main/2022/HCMUS-CTF%20Quals/4.%20SignMe/chal.py)
>
> nc 103.245.250.31 31850

`chal.py`

```py
import hashlib
from Crypto.Util.number import *
from random import randint
from os import urandom
from base64 import b64decode, b64encode
from hashlib import sha256

with open("../flag.txt") as file:
    FLAG = file.read()

class SignatureScheme:
    def __init__(self) -> None:
        self.N = len(FLAG)
        assert self.N == 32

        self.p = 99489312791417850853874793689472588065916188862194414825310101275999789178243
        self.x = randint(1, self.p - 1)
        self.g = randint(1, self.p - 1)
        self.y = pow(self.g, self.x, self.p)
        self.coef = [randint(1, self.p - 1) for _ in range(self.N)]

        self.sign_attempt = self.N

    def sign(self, pt):
        if self.sign_attempt == 0:
            print("Sorry, no more attempt to sign")
            return (0, 0)
        else:
            try:
                msg = b64decode(pt)
                
                if (len(msg) > self.N): # I know you are hecking :(((
                    return (0, 0)
                
                k = sum([coef * m for coef, m in zip(self.coef, msg)])
                if k % 2 == 0: # Just to make k and p-1 coprime :)))
                    k += 1
                
                r = pow(self.g, k, self.p)
                h = bytes_to_long(sha256(pt).digest())
                s = ((h - self.x * r) * inverse(k, self.p - 1)) % (self.p - 1)
                self.sign_attempt -= 1
                return (r, s)
            except:
                print('Please send message in base64 encoding')

    def verify(self, pt, r, s):
        if not 0 < r < self.p:
            return False
        if not 0 < s < self.p - 1:
            return False
        h = bytes_to_long(sha256(pt).digest())
        return pow(self.g, h, self.p) == (pow(self.y, r, self.p) * pow(r, s, self.p)) % self.p   

    def get_flag(self):
        try:
            test = b64encode(urandom(self.N))
            print("Could you sign this for me: ", test.decode())
            r = b64decode(input('Input r: '))
            s = b64decode(input('Input s: '))
            if self.verify(test, bytes_to_long(r), bytes_to_long(s)):
                print("Congratulation, this is your flag: ", FLAG)
                exit(0)
            else:
                print("Sorry, that is not my signature")
                exit(-1)
        except Exception as e:
            print(e)
            print("Please send data in base64 encoding")

    def menu(self):
        print(f"You have only {self.sign_attempt} attempts left")
        print("0. Get public key")
        print("1. Sign a message")
        print("2. Verify a message")
        print("3. Get flag")
        return int(input('Select an option: '))

    def main(self):
        print("Welcome to our sign server")
        while True:
            option = self.menu()

            if option == 0:
                print("g =", self.g)
                print("p =", self.p)
            elif option == 1:
                msg = input("Input message you want to sign: ").encode()
                r, s = self.sign(msg)
                print("Signature (r, s): ", (r, s))

            elif option == 2:
                msg = input('Your message: ').encode()
                r = b64decode(input('Input r: '))
                s = b64decode(input('Input s: '))
                if self.verify(msg, bytes_to_long(r), bytes_to_long(s)):
                    print("Valid signature")
                else:
                    print("Invalid signature")

            elif option == 3:
                self.get_flag()

            else:
                print("Stay away you hecker :(((")

c = SignatureScheme()
c.main()
```

Đọc qua source code thì mình có thể xác định được dạng bài của bài này chính là [DSA](https://ctf-wiki.mahaloz.re/crypto/signature/dsa/)

### Ý tưởng:
Mình sẽ gửi `msg = b'\0x00'*32` để `sum = 0` rồi suy ra `k = 1` sau đó lấy pt để tính ra private key `x`

[solve.py](https://github.com/longkd719/Writeups/blob/main/2022/HCMUS-CTF%20Quals/4.%20SignMe/solve.py)

```py
import base64
from pwn import remote
from Crypto.Util.number import *
from hashlib import sha256
import sys
while True:
    try:
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
        break
    except:
        pass
```
Ta thu được `FLAG: HCMUS-CTF{B4se64_15_1nt3r3stin9}`
