#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import time
import requests
import json
from pwn import *

# def solve_pow(r):
#     prefix = r.recvline().decode().split("'")[1]
#     print(time.time(), "solving pow ...", f'prefix=[{prefix}]')
#     solved = b''
#     for i in range(1000000000):
#         h = hashlib.sha1((prefix + str(i)).encode()).hexdigest()
#         if h[:6] == '000000':
#             solved = str(i).encode()
#             print("solved =", solved)
#             break;
#     print(time.time(), "done.")

#     r.sendlineafter(b'string S: ', base64.b64encode(solved))

def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1]
    print(time.time(), "solving pow ...", f'prefix=[{prefix}]')
    my_auth = requests.auth.HTTPBasicAuth('unix111', 'up23bbunny')
    req = requests.get(f'http://140.113.208.119:48765/crack/{prefix}', auth=my_auth)
    r_dict = json.loads(req.text)
    solved = r_dict['suffix'].encode()
    print('solved = ', solved)
    print(time.time(), "done.")
    r.sendlineafter(b'string S: ', base64.b64encode(solved))


# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
