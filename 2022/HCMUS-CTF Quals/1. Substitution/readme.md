# Substitution
> Challenge cho 2 file: [chal.py](https://github.com/longkd719/Writeups/blob/main/2022/HCMUS-CTF%20Quals/1.%20Substitution/chal.py) và [msg_enc.txt](https://github.com/longkd719/Writeups/blob/main/2022/HCMUS-CTF%20Quals/1.%20Substitution/msg_enc.txt)
```
HO IFSBZXUFABDS, A QCVQZHZCZHXO IHBDKF HQ A GKZDXW XR KOIFSBZHOU HO JDHID COHZQ XR BNAHOZKYZ AFK FKBNAIKW JHZD ZDK IHBDKFZKYZ, HO A WKRHOKW GAOOKF, JHZD ZDK DKNB XR A PKS; ZDK "COHZQ" GAS VK QHOUNK NKZZKFQ (ZDK GXQZ IXGGXO), BAHFQ XR NKZZKFQ, ZFHBNKZQ XR NKZZKFQ, GHYZCFKQ XR ZDK AVXMK, AOW QX RXFZD. ZDK FKIKHMKF WKIHBDKFQ ZDK ZKYZ VS BKFRXFGHOU ZDK HOMKFQK QCVQZHZCZHXO BFXIKQQ ZX KYZFAIZ ZDK XFHUHOAN GKQQAUK. DKFK HQ ZDK RNAU: DIGCQ-IZR{ODAONCO_NHPKQ_ZX_BNAS_IFSBZXUFAG}
```
AIzzzz bài này mình cũng không cần phải đọc source làm gì
Nhìn vào msg_enc thì mình liền ném hết vào trong [tool](https://www.dcode.fr/monoalphabetic-substitution) để decrypt substitition và liền ra flag 

![](https://github.com/longkd719/Writeups/blob/main/2022/HCMUS-CTF%20Quals/1.%20Substitution/image.png)
> *`FLAG: HCMUS-CTF{NHANLUN_LIKES_TO_PLAY_CRYPTOGRAM}`*
