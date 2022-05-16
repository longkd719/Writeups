# Substitution2
> Challenge cho 2 file [chal.py](https://github.com/longkd719/Writeups/blob/main/2022/HCMUS-CTF/2.%20Substitution2/chal.py) và [msg_enc.txt](https://github.com/longkd719/Writeups/blob/main/2022/HCMUS-CTF/2.%20Substitution2/msg_enc.txt)

`chal.py`
```py
from random import shuffle

ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
n = len(ALPHABET)
sbox = [i for i in range(n)]
shuffle(sbox)

def transform(msg, offset):
    msg = ALPHABET.index(msg)
    return (sbox[msg] + offset) % n

msg = ''
with open('../Secret/msg.txt') as file:
    msg = file.read().upper()

special_symbols = "`~!@#$%&*()-=+[]\\;',./{}|:\"<>? "
for ch in special_symbols:
    msg = msg.replace(ch, '')

msg_enc = ''
offset = 1
for i in range(0, len(msg), 5):
    for j in range(5):
        print(j)
        # Sorry the code looks so ugly, but you know what it does :))
        if msg[i+j] == '_':
            msg_enc += '_'
        else:
            msg_enc += ALPHABET[transform(msg[i+j], offset)]
    offset = (offset * 3 + 4) % n
    
with open('msg_enc.txt', 'w+') as file:
    file.write(msg_enc)
```


Nhìn qua output thì mình thấy bài này khác với bài trước đó vì nó loại bỏ các kí tự đặc biệt `special_symbols` cho nên ta không thể ném vào tool như bài trước được
### Ý tưởng:
Theo như source code thì ta biết được rằng msg được mã hoá theo công thức sau: `msg_enc = subs(shift(msg,offset), sbox)` Mà `offset` được tính bằng công thức ` offset = (offset * 3 + 4) % n` như trong source. Từ đó ta có thể giải được bài này bằng cách:

`msg = inv_subs(inv_shift(msg_enc, offset), sbox)` 

### Tìm inv_shift(msg_enc, offset):
```py
ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
ct="MOTRVZLGEYDQCWBHDHDLYJZDQDESRKSAGGUYMNLYDWOFGTFDGOZMGAQKZMFEGTFESLWBYWRYRMESHFETMMZUJQDVYIJLHFSMNQLJIKCREGTODKGGBUHFESGQOYHFQSUZXBRDYFRDJKOTQOZUMSRMRFDSAUSUYGMZMFBEFAXHDGUNRBMFIDIKETGGTUJMAYEFBMIVQUEYMAZJYHRKIMSEJKDMYKKJQHNCRDKMGUYMKYLOTQORMKOHFJMYLGROFGRFSDTAMNQLQKRDOCHDUESLWBYWRREQQFXKSOZMAZPIBEYIJJKFBANKZTPAQDVZSOTOYUZKNURZFBTGUTOQLYLDQDQMRGUTJKJMGQPHIDNQHODKMKZMMZMBERMJTXLHWUYPJIMVFOOSPUDYLDJJRREEQFXMMSUZMAZHIBEYKJJKFUZVZYEBESRFKFDTLJZVAMQBRRGSKHFJAUDKTMRNMTDTFGJMAZPIBEKMTRVTFMKZMMRMBFDGYPHAYKZLWCFBSCSFQVSWZMZIESYHTDAGMFQ_JVYYRB_QFX_PKKEYKVSQJREHA_HD_JZGBMR_FBFG_HG"
n = len(ALPHABET)
m=""
offset=1
for i in range(0,len(ct),5):
    for j in range(5):
        if ct[i+j]=='_':
            m+='_'
        else:
            a=ALPHABET.index(ct[i+j])-offset
            if a<0:
                a+=n
            m+=ALPHABET[a]
    offset = (offset * 3 + 4) % n
print(m)
```
**output:**
```
LNSQUSEZXRERDXCGCGCKRCSWJEFTSLRZFFTRFGEREXPGHSECFNSFZTJLANGFFSEDREPURPSZSNFRGEDSFFSNCREWZJIKGERFGJECJLDSFFSNCJZZUNAGFTHRNXGEPLNSQUSEZGSCIJNSJHSNFTSNSGCRZTRNRZFSNGCFGZWGCFNGKUFGJEJLDSFFSNCFTRFGCNJUPTDXFTSCRISLJNRDIJCFRDDCRIODSCJLFTRFDREPURPSLJNGECFREZSPGHSERCSZFGJEJLSEPDGCTDREPURPSSFRREWJRNSFTSIJCFZJIIJEATGDSMQBREWYRNSNRNSDGVSAGCSFTSNJEREWRERNSFTSIJCFZJIIJEORGNCJLDSFFSNCFSNISWKGPNRICJNWGPNROTCREWCCSSFFREWLLRNSFTSIJCFZJIIJENSOSRFCFTSEJECSECSOTNRCSSFRJGECTNWDUNSONSCSEFCFTSIJCFLNSQUSEFDSFFSNCGEFXOGZRDSEPDGCTDREPURPSFSBFTZIUCZFLEJ_CORZSC_REW_OJDXRDOTRKSFGZ_GC_CSZUNS_GCEF_GF
```
Tiếp tục ném đoạn output này vào [tool](https://www.dcode.fr/monoalphabetic-substitution) ta liền thu được flag

![](https://github.com/longkd719/Writeups/blob/main/2022/HCMUS-CTF/2.%20Substitution2/image.png)

Thêm vài kí tự cho đúng format `FLAG: HCMUS-CTF{NO_SPACES_AND_POLYALPHABETIC_IS_SECURE_ISNT_IT}`
