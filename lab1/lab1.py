#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
from pow import solve_pow
import base64
import struct

def challenge(r):
    text = r.recvuntil(b"?")
    print(text)
    s = text.decode().split(": ")[1]
    s = s.split(" ")[:3]
    question =''.join(s)
    result = eval(question)
    print('===============================================')
    print(bin(result))
    print("result.bit_length: ",result.bit_length())
    print("result.bit_lenght+7//8= ",(result.bit_length()+7)//8)
    x = result.to_bytes((result.bit_length()+7)//8, byteorder = 'little')
    print(question)
    print(result)
    print(type(x))
    result = base64.b64encode(x)
    
    print(result)
    r.sendlineafter(b"", result)


r = remote('up23.zoolab.org', 10363)
solve_pow(r)
iteration = int(r.recvuntil(b"challenges").decode().split(" ")[-2])
for it in range(iteration):
    challenge(r)
r.interactive()
r.close()


