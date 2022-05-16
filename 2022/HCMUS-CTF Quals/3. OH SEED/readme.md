# OH SEED
> nc 103.245.250.31 30620
### Kết nối server
![](https://github.com/longkd719/Writeups/blob/main/2022/HCMUS-CTF%20Quals/3.%20OH%20SEED/image.png)

Ta thấy server cho ta 665 số ngẫu nhiên và server yêu cầu chúng ta nhập số mà nó random tiếp theo

Bài này mình biết được đây là bài dạng [Mersenne Twister Recover](https://en.wikipedia.org/wiki/Mersenne_Twister)

Các số random trong bài này được tạo bởi một seed riêng. Mục tiêu của chúng ta là phải khôi phục lại cái seed đó. Ở đây mình đã có một [tool](https://github.com/eboda/mersenne-twister-recover) sẵn để có thể solve bài này.

[solve.py:](https://github.com/longkd719/Writeups/blob/main/2022/HCMUS-CTF%20Quals/3.%20OH%20SEED/solve.py)

```py
import random


class MT19937Recover:
    """Reverses the Mersenne Twister based on 624 observed outputs.
    The internal state of a Mersenne Twister can be recovered by observing
    624 generated outputs of it. However, if those are not directly
    observed following a twist, another output is required to restore the
    internal index.
    See also https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode .
    """
    def unshiftRight(self, x, shift):
        res = x
        for i in range(32):
            res = x ^ res >> shift
        return res

    def unshiftLeft(self, x, shift, mask):
        res = x
        for i in range(32):
            res = x ^ (res << shift & mask)
        return res

    def untemper(self, v):
        """ Reverses the tempering which is applied to outputs of MT19937 """

        v = self.unshiftRight(v, 18)
        v = self.unshiftLeft(v, 15, 0xefc60000)
        v = self.unshiftLeft(v, 7, 0x9d2c5680)
        v = self.unshiftRight(v, 11)
        return v

    def go(self, outputs, forward=True):
        """Reverses the Mersenne Twister based on 624 observed values.
        Args:
            outputs (List[int]): list of >= 624 observed outputs from the PRNG.
                However, >= 625 outputs are required to correctly recover
                the internal index.
            forward (bool): Forward internal state until all observed outputs
                are generated.
        Returns:
            Returns a random.Random() object.
        """

        result_state = None

        assert len(outputs) >= 624       # need at least 624 values

        ivals = []
        for i in range(624):
            ivals.append(self.untemper(outputs[i]))

        if len(outputs) >= 625:
            # We have additional outputs and can correctly
            # recover the internal index by bruteforce
            challenge = outputs[624]
            for i in range(1, 626):
                state = (3, tuple(ivals+[i]), None)
                r = random.Random()
                r.setstate(state)

                if challenge == r.getrandbits(32):
                    result_state = state
                    break
        else:
            # With only 624 outputs we assume they were the first observed 624
            # outputs after a twist -->  we set the internal index to 624.
            result_state = (3, tuple(ivals+[624]), None)

        rand = random.Random()
        rand.setstate(result_state)

        if forward:
            for i in range(624, len(outputs)):
                assert rand.getrandbits(32) == outputs[i]

        return rand


from pwn import *
io=connect("103.245.250.31",30620)
io.recvuntil(b"Here is the first 665 random numbers.\n")
list=io.recvline()[:-1].decode()
list=[int(i)for i in list.split()]
mtb = MT19937Recover()
r2 = mtb.go(list)

a=r2.getrandbits(32)
io.recvuntil(b"Now it's your turn to guess the last random number:\n")
io.sendline(str(a).encode())
print(io.recvline())
print(io.recvline())
print(io.recvline())
#HCMUS-CTF{r4nd0m-1s-n0t-r4nd0m}
```

Server trả lại cho mình quả `FLAG: HCMUS-CTF{r4nd0m-1s-n0t-r4nd0m}`


