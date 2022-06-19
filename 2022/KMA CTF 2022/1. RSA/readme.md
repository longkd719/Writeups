# RSA
> Đề bài cho file [RSA.py](https://github.com/longkd719/Writeups/blob/main/2022/KMA%20CTF%202022/1.%20RSA/RSA.py)
>
> *Author: ChiUyenXinhDep*

Từ source code thì ta có thể thấy được đề bài cho `N`, `e = 2 * 0x10001`, `ciphertext`, `p % 2**512` và `q >> 512`

Đầu tiên là mình thử factor `N` bằng [tool](http://factordb.com/) nhưng mà tạch luôn

Gọi `P = p % 2**512` và `Q = q >> 512` cho dễ viết nha

Ta đã biết được rằng p và q là 2 số nguyên tố rất lớn với 1024 bit, Q là 512 bit đầu của q
 
Mình đã sử dụng một bộ test mà mình đã tạo ra để thử các cách tìm ra p, q từ P, Q... và rồi mình phát hiện ra được rằng:

  - Tính `P1 = (N // (Q << 512))` ta sẽ thu được một số có 512 bit đầu của p
  
  - Sau đó tính `a = P1 // 2**512` và ta thu được một số xấp xỉ với `p // 2**512` (số a này là gần đúng vì mình đã thử rất nhiều test và nó chỉ có thể nằm trong phạm vi từ a-1 đến a+1)
  
  - Từ số a ta có thể tính được số p đúng bằng cách tính `p = a * 2**512 + P` (với a là 3 số nằm trong phạm vi từ a-1 đến a+1) sao cho số p là số nguyên tố
  
  - Từ p ta có thể suy ra được `q = N // p`
  
```
p = 127988824293683226968236082701011718696817107470672227731163865962477851740174835162164959409245677977249490154049919793163446003206128094715082693499360272728010088349538751449287502772209132886044463040746219298579632126390679272629698982949004636683326955740463908996386833676057193151616239500811580286679
q = 147751534267099351877382093613701283758967738927864606521528656696240917956339626096544353537347308479582553999484944970015280229759513837496809764538354655934751664226914674857525165896301056177277912935544070486549032478537021664186817002540788838525718999518894333019171454948015116002836193256884998672203
```

Đừng có nghĩ tìm được p, q là có được tất cả :) nó vẫn chưa xong đâu :>

