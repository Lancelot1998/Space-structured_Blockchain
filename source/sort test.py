# -*- coding: utf-8 -*-
"""
    blockchain
    ~~~~~~~~~~

    Implements blockchain data structure and rules of validation

    :author: hank
"""

import hashlib
import time
import struct
from source.blockchain import *
from typing import List, Tuple, NewType
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import \
    Encoding, PublicFormat, load_pem_public_key, load_der_private_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend
from source.utility import n_bytes
from source.errors import *
from cryptography.hazmat.primitives import hashes, hmac
from enum import Enum, unique
from functools import reduce
from source.utility import bin2int
import queue
import threading
import os
import json
import sys
import random
import codecs
import time

CPU = NewType('CPU', int)
RAM = NewType('RAM', int)
BANDWIDTH = NewType('BANDWIDTH', int)
ASSET = NewType('ASSET', float)
PUBLIC_KEY_HASH = NewType('PUBLIC_KEY_HASH', bytes)
TXID = NewType('TXID', bytes)
OUTPUT_INDEX = NewType('OUTPUT_INDEX', int)
SIGNATURE = NewType('SIGNATURE', bytes)

BLENGTH_PUBLIC_KEY_HASH = 32
BLENGTH_INT = 4
BLENGTH_TXID = 32
BLENGTH_DOUBLE = 8
BLENGTH_BLOCKHASH = 32
BLENGTH_PUBKEY = 174
INIT_HASH = b'G\xfdk\x88\xda5\xff\x8c\x97t\x9f\xcb\xe0\xa8\x07S\x8b9t:.9\x1d\xee\xf4\xb1\xda\xd1r\xaf\xfcu'
# a = []
# print(time.time())
# for i in range(10000000):
#     a.append(i)
# print(time.time())
# for i in a:
#     if i == 9990000:
#         print('ok')
#         print(time.time())

block = Block.unpack(b'G\xfdk\x88\xda5\xff\x8c\x97t\x9f\xcb\xe0\xa8\x07S\x8b9t:.9\x1d\xee\xf4\xb1\xda\xd1r\xaf'
                     b'\xfcu\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x99\x01\x00\x00O\x1e,-\xe1\xa0!\x16D\x87\xcc\x923\xf7\xf6\xca\xad\xd1\t\x8eV\xdc\xe8t}N'
                     b'\xfa\x8af\xbe\xe7\xef\x01\x00\x00\x00\x89\x92N\xd8h\xb5\xd6A\xae\x00\x00\x00D\x00\x00'
                     b'\x00(\x00\x00\x00-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE7G2oklVAO7P'
                     b'mkOwFKyoRLRZijrrlErST\neOrOEcxOUHG1ywjGYLLTWV1vvGl6rdL0wxwsqhl4c3uMqWHHA8sYXg==\n-----EN'
                     b'D PUBLIC KEY-----\n\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06\xf5{\x89^4\x1b\xb3\x95z\x04}'
                     b'\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06'
                     b'\xf5{\x89^4\x1b\xb3\x95z\x04}\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\x00'
                     b'\x00E@\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e\x9b\xe2\xb2\xd9\xe1\x9c\x80'
                     b'\x10H\xb6\xa1\xfd\x02\xbf0E\x02!\x00\xfa\xff2\x10\x08\x18\xce~\x10\xb3\xe5\xc7y\xfd]\xd4'
                     b'\x13tj\x9bx\n3-\xef\xe5\t\xe3\xd6R+\x16\x02 \x17L\x07\xb5E c\xc8\xf5l\xc7\xc1\xa7BM'
                     b'\xbb0Y/\x9b\x89\xb0a_9\x0bi\xe2*\x0b\xda\xf9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
block.hash = b'0x000000000000000000000000000001'
block.show_block()
block1 = Block.unpack(b'G\xfdk\x88\xda5\xff\x8c\x97t\x9f\xcb\xe0\xa8\x07S\x8b9t:.9\x1d\xee\xf4\xb1\xda\xd1r\xaf'
                      b'\xfcu\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x99\x01\x00\x00O\x1e,-\xe1\xa0!\x16D\x87\xcc\x923\xf7\xf6\xca\xad\xd1\t\x8eV\xdc\xe8t}N'
                      b'\xfa\x8af\xbe\xe7\xef\x01\x00\x00\x00\x89\x92N\xd8h\xb5\xd6A\xae\x00\x00\x00D\x00\x00'
                      b'\x00(\x00\x00\x00-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE7G2oklVAO7P'
                      b'mkOwFKyoRLRZijrrlErST\neOrOEcxOUHG1ywjGYLLTWV1vvGl6rdL0wxwsqhl4c3uMqWHHA8sYXg==\n-----EN'
                      b'D PUBLIC KEY-----\n\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06\xf5{\x89^4\x1b\xb3\x95z\x04}'
                      b'\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06'
                      b'\xf5{\x89^4\x1b\xb3\x95z\x04}\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\x00'
                      b'\x00E@\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e\x9b\xe2\xb2\xd9\xe1\x9c\x80'
                      b'\x10H\xb6\xa1\xfd\x02\xbf0E\x02!\x00\xfa\xff2\x10\x08\x18\xce~\x10\xb3\xe5\xc7y\xfd]\xd4'
                      b'\x13tj\x9bx\n3-\xef\xe5\t\xe3\xd6R+\x16\x02 \x17L\x07\xb5E c\xc8\xf5l\xc7\xc1\xa7BM'
                      b'\xbb0Y/\x9b\x89\xb0a_9\x0bi\xe2*\x0b\xda\xf9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

block1.hash = b'0x000000000000000000000000000002'
block1.previous_hash = b'0x000000000000000000000000000001'
block1.show_block()
block2 = Block.unpack(b'G\xfdk\x88\xda5\xff\x8c\x97t\x9f\xcb\xe0\xa8\x07S\x8b9t:.9\x1d\xee\xf4\xb1\xda\xd1r\xaf'
                      b'\xfcu\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x99\x01\x00\x00O\x1e,-\xe1\xa0!\x16D\x87\xcc\x923\xf7\xf6\xca\xad\xd1\t\x8eV\xdc\xe8t}N'
                      b'\xfa\x8af\xbe\xe7\xef\x01\x00\x00\x00\x89\x92N\xd8h\xb5\xd6A\xae\x00\x00\x00D\x00\x00'
                      b'\x00(\x00\x00\x00-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE7G2oklVAO7P'
                      b'mkOwFKyoRLRZijrrlErST\neOrOEcxOUHG1ywjGYLLTWV1vvGl6rdL0wxwsqhl4c3uMqWHHA8sYXg==\n-----EN'
                      b'D PUBLIC KEY-----\n\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06\xf5{\x89^4\x1b\xb3\x95z\x04}'
                      b'\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06'
                      b'\xf5{\x89^4\x1b\xb3\x95z\x04}\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\x00'
                      b'\x00E@\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e\x9b\xe2\xb2\xd9\xe1\x9c\x80'
                      b'\x10H\xb6\xa1\xfd\x02\xbf0E\x02!\x00\xfa\xff2\x10\x08\x18\xce~\x10\xb3\xe5\xc7y\xfd]\xd4'
                      b'\x13tj\x9bx\n3-\xef\xe5\t\xe3\xd6R+\x16\x02 \x17L\x07\xb5E c\xc8\xf5l\xc7\xc1\xa7BM'
                      b'\xbb0Y/\x9b\x89\xb0a_9\x0bi\xe2*\x0b\xda\xf9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

block2.hash = b'0x000000000000000000000000000003'
block2.previous_hash = b'0x000000000000000000000000000002'
block2.show_block()
block3 = Block.unpack(b'G\xfdk\x88\xda5\xff\x8c\x97t\x9f\xcb\xe0\xa8\x07S\x8b9t:.9\x1d\xee\xf4\xb1\xda\xd1r\xaf'
                      b'\xfcu\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x99\x01\x00\x00O\x1e,-\xe1\xa0!\x16D\x87\xcc\x923\xf7\xf6\xca\xad\xd1\t\x8eV\xdc\xe8t}N'
                      b'\xfa\x8af\xbe\xe7\xef\x01\x00\x00\x00\x89\x92N\xd8h\xb5\xd6A\xae\x00\x00\x00D\x00\x00'
                      b'\x00(\x00\x00\x00-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE7G2oklVAO7P'
                      b'mkOwFKyoRLRZijrrlErST\neOrOEcxOUHG1ywjGYLLTWV1vvGl6rdL0wxwsqhl4c3uMqWHHA8sYXg==\n-----EN'
                      b'D PUBLIC KEY-----\n\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06\xf5{\x89^4\x1b\xb3\x95z\x04}'
                      b'\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06'
                      b'\xf5{\x89^4\x1b\xb3\x95z\x04}\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\x00'
                      b'\x00E@\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e\x9b\xe2\xb2\xd9\xe1\x9c\x80'
                      b'\x10H\xb6\xa1\xfd\x02\xbf0E\x02!\x00\xfa\xff2\x10\x08\x18\xce~\x10\xb3\xe5\xc7y\xfd]\xd4'
                      b'\x13tj\x9bx\n3-\xef\xe5\t\xe3\xd6R+\x16\x02 \x17L\x07\xb5E c\xc8\xf5l\xc7\xc1\xa7BM'
                      b'\xbb0Y/\x9b\x89\xb0a_9\x0bi\xe2*\x0b\xda\xf9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

block3.hash = b'0x000000000000000000000000000004'
block3.previous_hash = b'0x000000000000000000000000000003'
block3.show_block()
block4 = Block.unpack(b'G\xfdk\x88\xda5\xff\x8c\x97t\x9f\xcb\xe0\xa8\x07S\x8b9t:.9\x1d\xee\xf4\xb1\xda\xd1r\xaf'
                      b'\xfcu\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x99\x01\x00\x00O\x1e,-\xe1\xa0!\x16D\x87\xcc\x923\xf7\xf6\xca\xad\xd1\t\x8eV\xdc\xe8t}N'
                      b'\xfa\x8af\xbe\xe7\xef\x01\x00\x00\x00\x89\x92N\xd8h\xb5\xd6A\xae\x00\x00\x00D\x00\x00'
                      b'\x00(\x00\x00\x00-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE7G2oklVAO7P'
                      b'mkOwFKyoRLRZijrrlErST\neOrOEcxOUHG1ywjGYLLTWV1vvGl6rdL0wxwsqhl4c3uMqWHHA8sYXg==\n-----EN'
                      b'D PUBLIC KEY-----\n\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06\xf5{\x89^4\x1b\xb3\x95z\x04}'
                      b'\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06'
                      b'\xf5{\x89^4\x1b\xb3\x95z\x04}\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\x00'
                      b'\x00E@\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e\x9b\xe2\xb2\xd9\xe1\x9c\x80'
                      b'\x10H\xb6\xa1\xfd\x02\xbf0E\x02!\x00\xfa\xff2\x10\x08\x18\xce~\x10\xb3\xe5\xc7y\xfd]\xd4'
                      b'\x13tj\x9bx\n3-\xef\xe5\t\xe3\xd6R+\x16\x02 \x17L\x07\xb5E c\xc8\xf5l\xc7\xc1\xa7BM'
                      b'\xbb0Y/\x9b\x89\xb0a_9\x0bi\xe2*\x0b\xda\xf9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

block4.hash = b'0x000000000000000000000000000005'
block4.previous_hash = b'0x000000000000000000000000000004'
block4.show_block()
block5 = Block.unpack(b'G\xfdk\x88\xda5\xff\x8c\x97t\x9f\xcb\xe0\xa8\x07S\x8b9t:.9\x1d\xee\xf4\xb1\xda\xd1r\xaf'
                      b'\xfcu\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x99\x01\x00\x00O\x1e,-\xe1\xa0!\x16D\x87\xcc\x923\xf7\xf6\xca\xad\xd1\t\x8eV\xdc\xe8t}N'
                      b'\xfa\x8af\xbe\xe7\xef\x01\x00\x00\x00\x89\x92N\xd8h\xb5\xd6A\xae\x00\x00\x00D\x00\x00'
                      b'\x00(\x00\x00\x00-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE7G2oklVAO7P'
                      b'mkOwFKyoRLRZijrrlErST\neOrOEcxOUHG1ywjGYLLTWV1vvGl6rdL0wxwsqhl4c3uMqWHHA8sYXg==\n-----EN'
                      b'D PUBLIC KEY-----\n\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06\xf5{\x89^4\x1b\xb3\x95z\x04}'
                      b'\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06'
                      b'\xf5{\x89^4\x1b\xb3\x95z\x04}\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\x00'
                      b'\x00E@\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e\x9b\xe2\xb2\xd9\xe1\x9c\x80'
                      b'\x10H\xb6\xa1\xfd\x02\xbf0E\x02!\x00\xfa\xff2\x10\x08\x18\xce~\x10\xb3\xe5\xc7y\xfd]\xd4'
                      b'\x13tj\x9bx\n3-\xef\xe5\t\xe3\xd6R+\x16\x02 \x17L\x07\xb5E c\xc8\xf5l\xc7\xc1\xa7BM'
                      b'\xbb0Y/\x9b\x89\xb0a_9\x0bi\xe2*\x0b\xda\xf9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

block5.hash = b'0x000000000000000000000000000006'
block5.previous_hash = b'0x000000000000000000000000000004'
block5.show_block()
block6 = Block.unpack(b'G\xfdk\x88\xda5\xff\x8c\x97t\x9f\xcb\xe0\xa8\x07S\x8b9t:.9\x1d\xee\xf4\xb1\xda\xd1r\xaf'
                      b'\xfcu\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x99\x01\x00\x00O\x1e,-\xe1\xa0!\x16D\x87\xcc\x923\xf7\xf6\xca\xad\xd1\t\x8eV\xdc\xe8t}N'
                      b'\xfa\x8af\xbe\xe7\xef\x01\x00\x00\x00\x89\x92N\xd8h\xb5\xd6A\xae\x00\x00\x00D\x00\x00'
                      b'\x00(\x00\x00\x00-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE7G2oklVAO7P'
                      b'mkOwFKyoRLRZijrrlErST\neOrOEcxOUHG1ywjGYLLTWV1vvGl6rdL0wxwsqhl4c3uMqWHHA8sYXg==\n-----EN'
                      b'D PUBLIC KEY-----\n\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06\xf5{\x89^4\x1b\xb3\x95z\x04}'
                      b'\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06'
                      b'\xf5{\x89^4\x1b\xb3\x95z\x04}\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\x00'
                      b'\x00E@\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e\x9b\xe2\xb2\xd9\xe1\x9c\x80'
                      b'\x10H\xb6\xa1\xfd\x02\xbf0E\x02!\x00\xfa\xff2\x10\x08\x18\xce~\x10\xb3\xe5\xc7y\xfd]\xd4'
                      b'\x13tj\x9bx\n3-\xef\xe5\t\xe3\xd6R+\x16\x02 \x17L\x07\xb5E c\xc8\xf5l\xc7\xc1\xa7BM'
                      b'\xbb0Y/\x9b\x89\xb0a_9\x0bi\xe2*\x0b\xda\xf9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

block6.hash = b'0x000000000000000000000000000007'
block6.previous_hash = b'0x000000000000000000000000000006'
block6.show_block()
block7 = Block.unpack(b'G\xfdk\x88\xda5\xff\x8c\x97t\x9f\xcb\xe0\xa8\x07S\x8b9t:.9\x1d\xee\xf4\xb1\xda\xd1r\xaf'
                      b'\xfcu\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x99\x01\x00\x00O\x1e,-\xe1\xa0!\x16D\x87\xcc\x923\xf7\xf6\xca\xad\xd1\t\x8eV\xdc\xe8t}N'
                      b'\xfa\x8af\xbe\xe7\xef\x01\x00\x00\x00\x89\x92N\xd8h\xb5\xd6A\xae\x00\x00\x00D\x00\x00'
                      b'\x00(\x00\x00\x00-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE7G2oklVAO7P'
                      b'mkOwFKyoRLRZijrrlErST\neOrOEcxOUHG1ywjGYLLTWV1vvGl6rdL0wxwsqhl4c3uMqWHHA8sYXg==\n-----EN'
                      b'D PUBLIC KEY-----\n\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06\xf5{\x89^4\x1b\xb3\x95z\x04}'
                      b'\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06'
                      b'\xf5{\x89^4\x1b\xb3\x95z\x04}\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\x00'
                      b'\x00E@\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e\x9b\xe2\xb2\xd9\xe1\x9c\x80'
                      b'\x10H\xb6\xa1\xfd\x02\xbf0E\x02!\x00\xfa\xff2\x10\x08\x18\xce~\x10\xb3\xe5\xc7y\xfd]\xd4'
                      b'\x13tj\x9bx\n3-\xef\xe5\t\xe3\xd6R+\x16\x02 \x17L\x07\xb5E c\xc8\xf5l\xc7\xc1\xa7BM'
                      b'\xbb0Y/\x9b\x89\xb0a_9\x0bi\xe2*\x0b\xda\xf9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

block7.hash = b'0x000000000000000000000000000008'
block7.previous_hash = b'0x000000000000000000000000000007'
block7.show_block()
block8 = Block.unpack(b'G\xfdk\x88\xda5\xff\x8c\x97t\x9f\xcb\xe0\xa8\x07S\x8b9t:.9\x1d\xee\xf4\xb1\xda\xd1r\xaf'
                      b'\xfcu\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x99\x01\x00\x00O\x1e,-\xe1\xa0!\x16D\x87\xcc\x923\xf7\xf6\xca\xad\xd1\t\x8eV\xdc\xe8t}N'
                      b'\xfa\x8af\xbe\xe7\xef\x01\x00\x00\x00\x89\x92N\xd8h\xb5\xd6A\xae\x00\x00\x00D\x00\x00'
                      b'\x00(\x00\x00\x00-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE7G2oklVAO7P'
                      b'mkOwFKyoRLRZijrrlErST\neOrOEcxOUHG1ywjGYLLTWV1vvGl6rdL0wxwsqhl4c3uMqWHHA8sYXg==\n-----EN'
                      b'D PUBLIC KEY-----\n\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06\xf5{\x89^4\x1b\xb3\x95z\x04}'
                      b'\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06'
                      b'\xf5{\x89^4\x1b\xb3\x95z\x04}\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\x00'
                      b'\x00E@\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e\x9b\xe2\xb2\xd9\xe1\x9c\x80'
                      b'\x10H\xb6\xa1\xfd\x02\xbf0E\x02!\x00\xfa\xff2\x10\x08\x18\xce~\x10\xb3\xe5\xc7y\xfd]\xd4'
                      b'\x13tj\x9bx\n3-\xef\xe5\t\xe3\xd6R+\x16\x02 \x17L\x07\xb5E c\xc8\xf5l\xc7\xc1\xa7BM'
                      b'\xbb0Y/\x9b\x89\xb0a_9\x0bi\xe2*\x0b\xda\xf9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

block8.hash = b'0x000000000000000000000000000009'
block8.previous_hash = b'0x000000000000000000000000000004'
block8.show_block()
block9 = Block.unpack(b'G\xfdk\x88\xda5\xff\x8c\x97t\x9f\xcb\xe0\xa8\x07S\x8b9t:.9\x1d\xee\xf4\xb1\xda\xd1r\xaf'
                      b'\xfcu\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x99\x01\x00\x00O\x1e,-\xe1\xa0!\x16D\x87\xcc\x923\xf7\xf6\xca\xad\xd1\t\x8eV\xdc\xe8t}N'
                      b'\xfa\x8af\xbe\xe7\xef\x01\x00\x00\x00\x89\x92N\xd8h\xb5\xd6A\xae\x00\x00\x00D\x00\x00'
                      b'\x00(\x00\x00\x00-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE7G2oklVAO7P'
                      b'mkOwFKyoRLRZijrrlErST\neOrOEcxOUHG1ywjGYLLTWV1vvGl6rdL0wxwsqhl4c3uMqWHHA8sYXg==\n-----EN'
                      b'D PUBLIC KEY-----\n\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06\xf5{\x89^4\x1b\xb3\x95z\x04}'
                      b'\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06'
                      b'\xf5{\x89^4\x1b\xb3\x95z\x04}\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\x00'
                      b'\x00E@\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e\x9b\xe2\xb2\xd9\xe1\x9c\x80'
                      b'\x10H\xb6\xa1\xfd\x02\xbf0E\x02!\x00\xfa\xff2\x10\x08\x18\xce~\x10\xb3\xe5\xc7y\xfd]\xd4'
                      b'\x13tj\x9bx\n3-\xef\xe5\t\xe3\xd6R+\x16\x02 \x17L\x07\xb5E c\xc8\xf5l\xc7\xc1\xa7BM'
                      b'\xbb0Y/\x9b\x89\xb0a_9\x0bi\xe2*\x0b\xda\xf9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

block9.hash = b'0x000000000000000000000000000010'
block9.previous_hash = b'0x000000000000000000000000000005'
block9.show_block()
# blockchain = list()
# blockchain.append(block)
# blockchain.append(block1)
# blockchain.append(block2)
# blockchain.append(block3)
# blockchain.append(block4)
# blockchain.append(block9)
# ass_chain = dict()
# ass_chain[block5] = (0, block3)
# ass_chain[block6] = (1, block5)
# ass_chain[block7] = (1, block6)
# ass_chain[block8] = (0, block3)
#
# print(time.time())


def ass_chain_length(block, ass_chain):
    flag = 1
    num = 0
    ruf_chain = list()
    # ruf_chain.append(block)
    while flag == 1:
        if block in ass_chain.keys():
            ruf_chain.append(block)
            flag = ass_chain[block][0]
            block = ass_chain[block][1]
            num += 1
        else:
            flag = 0
    return num, block, ruf_chain


# num, b, ruf = ass_chain_length(block7, ass_chain)
# print('num = ', num)
# b.show_block()


def main_chain_length(block, block_received):
    num = 0
    i = -1
    main_chain = list()
    while i < 0:
        print(i)
        if block_received.chain.queue[i] == block:
            # main_chain.append(block_received[i])
            print(main_chain)
            print('ok')
            break
        else:
            main_chain.append(block_received.chain.queue[i])
            print(main_chain)
            print('ok2')
            i -= 1
            num += 1
    return num, main_chain


# num2, main_chain = main_chain_length(block3, blockchain)
# print('num2 = ', num2)
# print(blockchain)
# print('main_chain', main_chain)
# print(blockchain)
# blockchain = blockchain[:-num2]
# print(blockchain)
# print(main_chain)
# print(ruf)
# print(block7)

# sort
# blockchain = blockchain[:-num2]
# print('ruf')
# print(blockchain)
# print(ruf)
# long = len(ruf)
# print(long)
# print(block5)
# print(block6)
# print(block7)
# print('\n')
# for i in ruf[::-1]:
#     blockchain.append(i)
#
# print(blockchain)
# print(time.time())
# a = queue.Queue()
# a.put(2)
# a.put(3)
# print(a.queue[1])
# for i in a.queue:
#     print(i)
#
# a = queue.Queue()
# a.put(2)
# a.put(3)
# a.put(5)
# # a = a.queue[:-1]
# for i in a.queue:
#     print(i)
# print(block.data.trans[0].opt.content)
# bloc = Blockchain()
# print(type(bloc.utxo.utxo))
# print(block.data.trans[0].ipt.content)


def chain_append(blockchain__, block_):
    if block_.previous_hash == blockchain__[-1].hash:
        blockchain__.append(block_)
        return True


# blockchain_ = list()
# blockchain_.append(block)
# blockchain_.append(block1)
# blockchain_.append(block2)
# blockchain_.append(block3)
# ass_chain_ = dict()
# ass_chain_[block5] = (0, block3)
# parentless = list()
#
#
# parentless.append(block9)
# parentless.append(block4)
#
# parentless.append(block7)
# parentless.append(block6)


def ass_func_for_pbp(ass_chain_, block):
    print('yes')
    for i in ass_chain_:
        if block.previous_hash == i.hash:
            ass_chain_[block] = (1, i)
            print('ok')
            return True
    return False


def parentless_block_process(blockchain__, parentless_):
    flag = 1
    while flag > 0:
        for i in parentless_:
            result = chain_append(blockchain__, i) or ass_func_for_pbp(ass_chain_, i)
            if result:
                print(i.hash)
                parentless_.remove(i)
                if len(parentless_) == 0:
                    flag = 0
                else:
                    flag = 1
                break

            flag = 0


# print(len(blockchain_), len(ass_chain_))
#
# parentless_block_process(blockchain_, parentless)
# print(len(blockchain_), len(ass_chain_))
# print('end')
#
# a = list()
# a.append(1)
# a.append(2)
# a.append(3)
# print(a[-1])
# block_1 = dict()
# block_1[1] = (2, 1)
# block_1[2] = (4, 3)
# if 3 in block_1.keys():
#     print('ok')

# print('------comprehensive test------\n')


# def longest_chain(blockchain, i):
#     for trans in i.data.trans:
#         for j in range(len(trans.opt.content)):
#             if blockchain.utxo_two.exist((trans.txid, j)):
#                 del blockchain.utxo_two.utxo[(trans.txid, j)]
#             if blockchain.utxo.exist((trans.txid, j)):
#                 del blockchain.utxo.utxo[(trans.txid, j)]
#             else:
#                 pass
#         for j in range(len(trans.ipt.content)):
#             if trans.ipt.content[j] in blockchain.utxo_two.txo.keys():
#                 blockchain.utxo_two.utxo[trans.ipt.content[j]] = \
#                     blockchain.utxo_two.txo[trans.ipt.content[j]]
#                 del blockchain.utxo_two.txo[trans.ipt.content[j]]
#                 blockchain.utxo.utxo[trans.ipt.content[j]] = \
#                     blockchain.utxo.txo[trans.ipt.content[j]]
#                 del blockchain.utxo.txo[trans.ipt.content[j]]
#             else:
#                 pass

def longest_chain(block, blockchain, ass_chain):
    num_ass, block, ruf_chain = ass_chain_length(block, ass_chain)
    num_main, main_chain = main_chain_length(block, blockchain)
    if num_main >= num_ass:
        pass
    else:
        # delete blocks in ruf_chain
        for i in ruf_chain:
            del ass_chain[i]
        # delete blocks in main_chain

        for i in main_chain:
            blockchain.chain.queue.remove(i)
            blockchain.accepted_blocks_hash.remove(i.hash)

        # todo: delete all valid trans in removed blocks
        # todo: check block validation processes
        k = 0
        for i in main_chain[::-1]:
            if k == 0:
                ass_chain[i] = (1, block)
                k += 1
            else:
                ass_chain[i] = (0, main_chain[-k])
                k += 1
            # deal with trans
            for trans in i.data.trans:
                for j in range(len(trans.opt.content)):
                    if blockchain.utxo_two.exist((trans.txid, j)):
                        del blockchain.utxo_two.utxo[(trans.txid, j)]
                    if blockchain.utxo.exist((trans.txid, j)):
                        del blockchain.utxo.utxo[(trans.txid, j)]
                    else:
                        pass
                for j in range(len(trans.ipt.content)):
                    if trans.ipt.content[j] in blockchain.utxo_two.txo.keys():
                        print(blockchain.utxo_two.txo[trans.ipt.content[j]][1])
                        if blockchain.utxo_two.txo[trans.ipt.content[j]][1] in \
                                blockchain.accepted_blocks_hash:
                            print('yes ok')
                            blockchain.utxo_two.utxo[trans.ipt.content[j]] =  \
                                blockchain.utxo_two.txo[trans.ipt.content[j]]
                            del blockchain.utxo_two.txo[trans.ipt.content[j]]
                            blockchain.utxo.utxo[trans.ipt.content[j]] =  \
                                blockchain.utxo.txo[trans.ipt.content[j]]
                            del blockchain.utxo.txo[trans.ipt.content[j]]
                            print(blockchain.utxo_two.utxo[trans.ipt.content[j]])
                            print('okkkk')
                            if blockchain.utxo_two.utxo[trans.ipt.content[j]][1] in \
                                    blockchain.UTXO_num.keys():
                                blockchain. \
                                    UTXO_num[blockchain.utxo_two.utxo[trans.ipt.content[j]][1]] += 1
                            else:
                                blockchain. \
                                    UTXO_num[blockchain.utxo_two.utxo[trans.ipt.content[j]][1]] = 1
                        else:
                            pass
                    else:
                        pass
        print(blockchain.accepted_blocks)
        for i in ruf_chain[::-1]:
            print('yes ok')
            if i.hash in blockchain.accepted_blocks.keys():
                del blockchain.accepted_blocks[i.hash]
                print('\nin\n')
            blockchain.add_block(i)


b = b'\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06\xf5{\x89^4\x1b\xb3\x95z\x04}\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E'
priv_key = load_der_private_key(
    b'0\x81\x84\x02\x01\x000\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00\n\x04m0k\x02\x01\x01\x04 '
    b'\xa6qo\xd3\x95}e\xeb\x0f\xa2\xc3U\xa5\xf2v\x85\x19\xbc@\xf7\xfd\xcb^\xa2\xe3\x96N\xff\nh\xd0\x85\xa1D'
    b'\x03B\x00\x04\xecm\xa8\x92U@;\xb3\xe6\x90\xec\x05+*\x11-\x16b\x8e\xba\xe5\x12\xb4\x93x\xea\xce\x11'
    b'\xccNPq\xb5\xcb\x08\xc6`\xb2\xd3Y]o\xbciz\xad\xd2\xf4\xc3\x1c,\xaa\x19xs{\x8c\xa9a\xc7\x03\xcb\x18^',
    None,
    default_backend()
)

ipt = TransInput([(TXID(b), OUTPUT_INDEX(0))], PUBLIC_KEY_HASH(b))
opt = TransOutput([(ASSET(42), PUBLIC_KEY_HASH(b'\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e\x9b\xe2\xb2'
                                               b'\xd9\xe1\x9c\x80\x10H\xb6\xa1\xfd\x02\xbf'))])

trans = Transaction(ipt, opt)
trans.ready(priv_key)

# print(trans.txid)

prikey1 = b'-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg64DiDBUkuGC5rrTfH6uy\nHt6vhvHrMH' \
          b'j3Gm64SZtdqtKhRANCAATMIeaIK4vT0ni00F6GGW40qioinPFgXjsj\n6sZGivW9Ipj+zcDfPc7RxZuFeKFmbtVaUXZ877DM4C8ELZs2D' \
          b'PVQ\n-----END PRIVATE KEY-----\n'
prikey1 = prikey1.replace(b'\r\n', b'\n')
prikey1 = prikey1.replace(b'\\n', b'\n')

private_key = load_pem_private_key(prikey1, None, default_backend())
public_key = private_key.public_key()
serialized_public = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo)
sha = hashlib.sha256()
# print(serialized_public)
sha.update(serialized_public)
public_key_hash = sha.digest()
serialized_dest = b'-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE3Cpts3oJsp0H30X1D3VjMJoTw9zoYuYA\n3f+' \
                  b'WQtU1TUbs3oJHYmBKcrMyhfuIlPfoCc7zIT3ySmb1+QToHvO1vw==\n-----END PUBLIC KEY-----\n'

sha = hashlib.sha256()
sha.update(serialized_dest)
dest_hash = sha.digest()
ipt1 = TransInput([(TXID(block.data.trans[0].txid), OUTPUT_INDEX(0))], public_key_hash)
opt1 = TransOutput([(ASSET(21), dest_hash), (21, dest_hash)])

trans1 = Transaction(ipt1, opt1)
trans1.ready(private_key)
block3.data.trans.append(trans1)

prikey2 = b'-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg9oPl10la6fkHb2Cp8p3H\nSwvuj0WYpY' \
          b'jg2zoWT6YBpIWhRANCAATcKm2zegmynQffRfUPdWMwmhPD3Ohi5gDd\n/5ZC1TVNRuzegkdiYEpyszKF+4iU9+gJzvMhPfJKZvX5BOge8' \
          b'7W/\n-----END PRIVATE KEY-----\n'
prikey2 = prikey2.replace(b'\r\n', b'\n')
prikey2 = prikey2.replace(b'\\n', b'\n')

private_key = load_pem_private_key(prikey2, None, default_backend())
public_key = private_key.public_key()
serialized_public = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo)
sha = hashlib.sha256()
sha.update(serialized_public)
public_key_hash = sha.digest()
serialized_dest = b'-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE4PojJlvYKaEeFZFInOVKtAq2wEQuzd4P\nMK' \
                  b'RKXu2Lt0CLKY9ttcIjvnj0Sps785ygQDLEh6tUHfR4MU6MDW8xAg==\n-----END PUBLIC KEY-----\n'
sha = hashlib.sha256()
sha.update(serialized_dest)
dest_hash = sha.digest()
ipt2 = TransInput([(TXID(block3.data.trans[1].txid), OUTPUT_INDEX(0))], public_key_hash)
opt2 = TransOutput([(ASSET(11), dest_hash), (10, dest_hash)])

trans2 = Transaction(ipt2, opt2)
trans2.ready(private_key)
block4.data.trans.append(trans2)

prikey3 = b'-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg9oPl10la6fkHb2Cp8p3H\nSwvuj0WYpY' \
          b'jg2zoWT6YBpIWhRANCAATcKm2zegmynQffRfUPdWMwmhPD3Ohi5gDd\n/5ZC1TVNRuzegkdiYEpyszKF+4iU9+gJzvMhPfJKZvX5BOge8' \
          b'7W/\n-----END PRIVATE KEY-----\n'
prikey3 = prikey3.replace(b'\r\n', b'\n')
prikey3 = prikey3.replace(b'\\n', b'\n')

private_key = load_pem_private_key(prikey3, None, default_backend())
public_key = private_key.public_key()
serialized_public = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo)
sha = hashlib.sha256()
sha.update(serialized_public)
public_key_hash = sha.digest()
serialized_dest = b'-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE4PojJlvYKaEeFZFInOVKtAq2wEQuzd4P\nMK' \
                  b'RKXu2Lt0CLKY9ttcIjvnj0Sps785ygQDLEh6tUHfR4MU6MDW8xAg==\n-----END PUBLIC KEY-----\n'
sha = hashlib.sha256()
sha.update(serialized_dest)
dest_hash = sha.digest()
ipt3 = TransInput([(TXID(block3.data.trans[1].txid), OUTPUT_INDEX(1))], public_key_hash)
opt3 = TransOutput([(ASSET(2), dest_hash), (ASSET(19), dest_hash)])

trans3 = Transaction(ipt3, opt3)
trans3.ready(private_key)
block5.data.trans.append(trans3)
# block5.data.trans.append(trans2)
print('\n------end------\n')

blockchain_test = Blockchain()

blockchain_test.add_block(block1)
print(len(blockchain_test.chain.queue))
blockchain_test.add_block(block2)
print(len(blockchain_test.chain.queue))
blockchain_test.add_block(block3)
blockchain_test.add_block(block3)
print(len(blockchain_test.chain.queue))
blockchain_test.add_block(block4)
print(len(blockchain_test.chain.queue))
print(blockchain_test.accepted_blocks_hash)
blockchain_test.add_block(block5)
blockchain_test.add_block(block5)
if block5.hash in blockchain_test.accepted_blocks_hash or \
        blockchain_test.accepted_blocks[block5.hash] > 1:
    print('pass5')
else:
    print('pass6')
ass_chain_test = dict()
ass_chain_test[block5] = (0, block3)
ass_chain_test[block6] = (1, block5)
ass_chain_test[block7] = (1, block6)

for i in blockchain_test.chain.queue:
    print(i.hash)
for i in blockchain_test.accepted_blocks_hash:
    print(i)
# print(blockchain_test.utxo.utxo)
# print(blockchain_test.utxo_two.utxo)
# print(blockchain_test.UTXO_num)

# num, block, ruf = ass_chain_length(block6, ass_chain_test)
# print(num, block, ruf)
#
# num2, main_chain = main_chain_length(block, blockchain_test)
# print(num2, main_chain)

print('----before-----')
for i in blockchain_test.chain.queue:
    print(i.hash)
print(blockchain_test.utxo.utxo)
print(blockchain_test.utxo_two.utxo)

longest_chain(block7, blockchain_test, ass_chain_test)
print('----after-----')
for i in blockchain_test.chain.queue:
    print(i.hash)
print(blockchain_test.utxo.utxo)
print(blockchain_test.utxo_two.utxo)
print(blockchain_test.utxo.txo)
print(blockchain_test.utxo_two.txo)
print(ass_chain_test)
print(blockchain_test.accepted_blocks_hash)
print(blockchain_test.accepted_blocks)

bloc1 = Block.unpack(b'G\xfdk\x88\xda5\xff\x8c\x97t\x9f\xcb\xe0\xa8\x07S\x8b9t:.9\x1d\xee\xf4\xb1\xda\xd1r\xaf'
                     b'\xfcu\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x99\x01\x00\x00O\x1e,-\xe1\xa0!\x16D\x87\xcc\x923\xf7\xf6\xca\xad\xd1\t\x8eV\xdc\xe8t}N'
                     b'\xfa\x8af\xbe\xe7\xef\x01\x00\x00\x00\x89\x92N\xd8h\xb5\xd6A\xae\x00\x00\x00D\x00\x00'
                     b'\x00(\x00\x00\x00-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE7G2oklVAO7P'
                     b'mkOwFKyoRLRZijrrlErST\neOrOEcxOUHG1ywjGYLLTWV1vvGl6rdL0wxwsqhl4c3uMqWHHA8sYXg==\n-----EN'
                     b'D PUBLIC KEY-----\n\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06\xf5{\x89^4\x1b\xb3\x95z\x04}'
                     b'\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06'
                     b'\xf5{\x89^4\x1b\xb3\x95z\x04}\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\x00'
                     b'\x00E@\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e\x9b\xe2\xb2\xd9\xe1\x9c\x80'
                     b'\x10H\xb6\xa1\xfd\x02\xbf0E\x02!\x00\xfa\xff2\x10\x08\x18\xce~\x10\xb3\xe5\xc7y\xfd]\xd4'
                     b'\x13tj\x9bx\n3-\xef\xe5\t\xe3\xd6R+\x16\x02 \x17L\x07\xb5E c\xc8\xf5l\xc7\xc1\xa7BM'
                     b'\xbb0Y/\x9b\x89\xb0a_9\x0bi\xe2*\x0b\xda\xf9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
blockchain = Blockchain()
blockchain.add_block(block)
bloc2 = Block.unpack(b'G\xfdk\x88\xda5\xff\x8c\x97t\x9f\xcb\xe0\xa8\x07S\x8b9t:.9\x1d\xee\xf4\xb1\xda\xd1r\xaf'
                     b'\xfcu\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x99\x01\x00\x00O\x1e,-\xe1\xa0!\x16D\x87\xcc\x923\xf7\xf6\xca\xad\xd1\t\x8eV\xdc\xe8t}N'
                     b'\xfa\x8af\xbe\xe7\xef\x01\x00\x00\x00\x89\x92N\xd8h\xb5\xd6A\xae\x00\x00\x00D\x00\x00'
                     b'\x00(\x00\x00\x00-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE7G2oklVAO7P'
                     b'mkOwFKyoRLRZijrrlErST\neOrOEcxOUHG1ywjGYLLTWV1vvGl6rdL0wxwsqhl4c3uMqWHHA8sYXg==\n-----EN'
                     b'D PUBLIC KEY-----\n\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06\xf5{\x89^4\x1b\xb3\x95z\x04}'
                     b'\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06'
                     b'\xf5{\x89^4\x1b\xb3\x95z\x04}\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\x00'
                     b'\x00E@\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e\x9b\xe2\xb2\xd9\xe1\x9c\x80'
                     b'\x10H\xb6\xa1\xfd\x02\xbf0E\x02!\x00\xfa\xff2\x10\x08\x18\xce~\x10\xb3\xe5\xc7y\xfd]\xd4'
                     b'\x13tj\x9bx\n3-\xef\xe5\t\xe3\xd6R+\x16\x02 \x17L\x07\xb5E c\xc8\xf5l\xc7\xc1\xa7BM'
                     b'\xbb0Y/\x9b\x89\xb0a_9\x0bi\xe2*\x0b\xda\xf9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

for b in blockchain.chain.queue:
    print(b)
print(block)
if block != blockchain.chain.queue[0]:
    print('yes')
if block in blockchain.chain.queue:
    print('ok')
print('ok4')

if block2 in blockchain_test.chain.queue:
    print('0')
print(block.data.attachment.content)


class A:
    def __init__(self, a):
        self.a = a

    def ok(self):
        print(self.a)
        b = B(self)
        print(b.b)


class B:
    def __init__(self, A):
        self.b = A.a


a = A(2)
a.ok()
print(len(block1.hash))

a = b'\x12\x12'
a += b'\x12\x12'
print(a)
print(a[:1])
print(block.hash)

# Test 1, test of class: MacroBlockHeader, result: passed

private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
public_key = private_key.public_key()
sy = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
sha = hashlib.sha256()
sha.update(sy)
public_key_hash = sha.digest()

macro_block_header = MacroBlockHeader(0, 11.11, public_key_hash, [block.hash, block.hash, block.hash], 1)
print(macro_block_header.show_macro_block_header())
c = macro_block_header.b
c = MacroBlockHeader.unpack(c)
print(c.show_macro_block_header())

# Test 2, test of class: MacroBlockBody, result: passed
print('test2')
macro_block_body = MacroBlockBody(macro_block_header.hash, [block.hash, block.hash, block.hash], block.data.trans[0])
macro_block_body.ready(private_key)
print(macro_block_body.show_macro_block_body())
c = macro_block_body.b
c = MacroBlockBody.unpack(c)
print(c.show_macro_block_body())

# Test 3, test of function: add_macro_block_body_verifier, result: passed

print(time.time())
if macro_block_header.hash == macro_block_body.hash:
    b_pubkey = macro_block_body.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    sha = hashlib.sha256()
    sha.update(b_pubkey)
    public_key_hash = sha.digest()
    if macro_block_header.public_key_hash != public_key_hash:
        print('false')
    else:
        content = b''
        for i_ in macro_block_body.ref_hash:
            content += i_
        try:
            macro_block_body.public_key.verify(macro_block_body.signature,
                                               content, ec.ECDSA(hashes.SHA256()))
        except Exception:
            print('sig')
        else:
            print('ok')
print(time.time())


class A:
    def __init__(self, a_):
        self.a = a_


a1 = A(5)
a2 = A(2)
a3 = A(3)
l_ = list()
l_.append(a1)
l_.append(a2)
l_.append(a3)

print('l_', l_)
for i in l_:
    print(i.a)

# c = sorted(l_, key=lambda A: A.a)
l_.sort(key=lambda A: A.a)
for i in l_:
    print(i.a)
print(c)
print(blockchain_test.chain.queue)
print(sorted(blockchain_test.chain.queue, key=lambda C: C.hash))

a = dict()
a['0'] = 1
a['9'] = 10
a['90'] = 100
for i in a.keys():
    print(i)

print(OUTPUT_INDEX(0))
print(type(OUTPUT_INDEX(0)))

a = dict()
a[1] = 4
a[2] = 6

if 1 in a.keys():
    print('o')

i_ = 0
for index, i in enumerate(blockchain_test.chain.queue):
    if i.hash == b'0x3':
        print('ok')
        i_ = index

print(i_)
for i in blockchain_test.chain.queue:
    print(i.hash)
print('yes')

for i in range(len(blockchain_test.chain.queue) - i_):
    print(blockchain_test.chain.queue[i_ + i].hash)


print('\n\ncomprehensive test for linear blockchain structure\n\n')


def ass_chain_length(ass_chain, macro_block_header):
    flag = 1
    num = 0
    ruf_chain = list()

    while flag == 1:
        if macro_block_header in ass_chain.keys():
            ruf_chain.append(macro_block_header)
            flag = ass_chain[macro_block_header][0]
            macro_block_header = ass_chain[macro_block_header][1]
            num += 1
        else:
            flag = 0
    return num, macro_block_header, ruf_chain


def main_chain_length(macro_chain, macro_block_header):
    num = 0
    i = -1
    main_chain = list()
    while i < 0:
        if macro_chain.chain_.queue[i] == macro_block_header:
            # main_chain.append(block_received[i])
            break
        else:
            main_chain.append(macro_chain.chain_.queue[i])
            i -= 1
            num += 1
    return num, main_chain


def trans_retrieve(i_: MicroBlock, macro_chain):
    print('retrieve', macro_chain.utxo.utxo.items())
    for trans in i_.data.trans:
        for j in range(len(trans.opt.content)):
            if macro_chain.utxo_two.exist((trans.txid, j)):
                print('exist2\n')
                del macro_chain.utxo_two.utxo[(trans.txid, j)]
            if macro_chain.utxo.exist((trans.txid, j)):
                del macro_chain.utxo.utxo[(trans.txid, j)]
            else:
                pass
        for j in range(len(trans.ipt.content)):
            if trans.ipt.content[j] in macro_chain.utxo_two.txo.keys():
                if macro_chain.utxo_two.txo[trans.ipt.content[j]][1] in \
                        macro_chain.accepted_macro_block_header_hash:
                    print('exist\n')
                    macro_chain.utxo_two.utxo[trans.ipt.content[j]] = \
                        macro_chain.utxo_two.txo[trans.ipt.content[j]]
                    del macro_chain.utxo_two.txo[trans.ipt.content[j]]
                    macro_chain.utxo.utxo[trans.ipt.content[j]] = \
                        macro_chain.utxo.txo[trans.ipt.content[j]]
                    del macro_chain.utxo.txo[trans.ipt.content[j]]
                else:
                    pass
            else:
                pass


def processor_macro_block_body_write(content, macro_chain, cached_macro_block_body, cached_macro_block_header,
                                     ass_chain):
    flag = 0
    i_ = 0
    try:
        macro_block_body = MacroBlockBody.unpack(content)
    except Exception:
        return False
    else:
        print('a', macro_block_body.show_macro_block_body())
        if macro_block_body.hash in macro_chain.accepted_macro_block_bodies.keys():
            macro_chain.accepted_macro_block_bodies[macro_block_body.hash] += 1
        else:
            macro_chain.accepted_macro_block_bodies[macro_block_body.hash] = 1
        if macro_chain.accepted_macro_block_bodies[macro_block_body.hash] > 1:
            print('pass body')
            return False
        else:
            result = Verify.add_macro_block_body_verifier(macro_chain, macro_block_body)
            if not result:
                # micro_blocks of macro_block_body is lacking
                print('lacking micro_block')
                if macro_block_body not in cached_macro_block_body:
                    cached_macro_block_body.append(macro_block_body)
                return False
            else:
                print('ok yes')
                macro_chain.ref_micro_block[macro_block_body.hash] = list()
                for i_ in macro_chain.micro_block_pool:
                    if i_.hash in macro_block_body.ref_hash:
                        macro_chain.ref_micro_block[macro_block_body.hash].append(i_)

                result_ = macro_chain.add_macro_block_body(macro_block_body)
                if result_:
                    print(macro_chain.chain_.queue[-1].hash)
                    if macro_chain.chain_.queue[-1].hash == macro_block_body.hash:
                        print('yep')
                        macro_chain.add_trans(macro_block_body.hash)
                    else:
                        for index, i in enumerate(macro_chain.chain_.queue):
                            if i.hash == macro_block_body.hash:
                                i_ = index
                                print(i_)
                                break
                        print('kkk')
                        print('c', macro_chain.utxo.utxo.items())
                        for i in range(len(macro_chain.chain_.queue) - i_):
                            # add
                            if macro_chain.chain_.queue[i_ + i].hash in macro_chain.ref_micro_block.keys():
                                print('in', i_ + i)
                                for q in macro_chain.ref_micro_block[macro_chain.chain_.queue[i_ + i].hash]:
                                    trans_retrieve(q, macro_chain)
                        print('before', macro_chain.utxo.utxo.items())
                        for i in range(len(macro_chain.chain_.queue) - i_):
                            if macro_chain.chain_.queue[i_ + i].hash in macro_chain.ref_micro_block.keys():
                                macro_chain.add_trans(macro_chain.chain_.queue[i_ + i].hash)
                        print('after', macro_chain.utxo.utxo.items())
                    if macro_block_body in cached_macro_block_body:
                        cached_macro_block_body.remove(macro_block_body)
                    return True

                else:
                    for i in ass_chain.keys():
                        if i.hash == macro_block_body.hash:
                            flag = 1
                            break
                    if flag == 0:
                        for i in cached_macro_block_header:
                            if i.hash == macro_block_body.hash:
                                flag = 1
                                break

                    if flag == 0 and macro_block_body not in cached_macro_block_body:
                        cached_macro_block_body.append(macro_block_body)
                    if flag == 1 and macro_block_body in cached_macro_block_body:
                        cached_macro_block_body.remove(macro_block_body)
                    return False

    finally:
        pass


def longest_chain(ass_chain, macro_chain, macro_block_header):
    print('o j b k ---')
    num_ass, macro_block_header, ruf_chain = ass_chain_length(ass_chain, macro_block_header)
    print('okk')
    num_main, main_chain = main_chain_length(macro_chain, macro_block_header)
    print('ok9')
    print(len(ruf_chain))
    if num_main >= num_ass:
        pass
    else:
        # delete blocks in ruf_chain
        for i in ruf_chain:
            del ass_chain[i]
        # delete blocks in main_chain
        for i in main_chain:
            macro_chain.chain_.queue.remove(i)
            macro_chain.accepted_macro_block_header_hash.remove(i.hash)
            macro_chain.length -= 1
            # if i.hash in self.server.blockchain.UTXO_num:
            #     del self.server.blockchain.UTXO_num[i]
        k = 0
        print(len(main_chain))
        for i in main_chain[::-1]:
            if k == 0:
                ass_chain[i] = (1, macro_block_header)
                k += 1
            else:
                ass_chain[i] = (0, main_chain[-k])
                k += 1
            # deal with trans
            print('deal with trans', macro_chain.utxo.utxo.items())
            if i.hash in macro_chain.ref_micro_block.keys():
                print('in in')
                for i_ in macro_chain.ref_micro_block[i.hash]:
                    for trans in i_.data.trans:
                        print(trans.show_trans())
                        for j in range(len(trans.opt.content)):
                            if macro_chain.utxo_two.exist((trans.txid, j)):
                                print('exist\n')
                                del macro_chain.utxo_two.utxo[(trans.txid, j)]
                            if macro_chain.utxo.exist((trans.txid, j)):
                                del macro_chain.utxo.utxo[(trans.txid, j)]

                        for j in range(len(trans.ipt.content)):
                            if trans.ipt.content[j] in macro_chain.utxo_two.txo.keys():
                                if macro_chain.utxo_two.txo[trans.ipt.content[j]][1] in \
                                        macro_chain.accepted_macro_block_header_hash:
                                    macro_chain.utxo_two.utxo[trans.ipt.content[j]] = \
                                        macro_chain.utxo_two.txo[trans.ipt.content[j]]
                                    del macro_chain.utxo_two.txo[trans.ipt.content[j]]
                                    macro_chain.utxo.utxo[trans.ipt.content[j]] = \
                                        macro_chain.utxo.txo[trans.ipt.content[j]]
                                    del macro_chain.utxo.txo[trans.ipt.content[j]]

        for i in ruf_chain[::-1]:
            print('timestamp', i.timestamp)
            if i.hash in macro_chain.accepted_macro_block_headers.keys():
                del macro_chain.accepted_macro_block_headers[i.hash]

            macro_chain.add_macro_block_header(i)
            if i.hash in macro_chain.ref_micro_block.keys():
                print('oj')
                macro_chain.add_trans(i.hash)


def parentless_macro_block_header_process(macro_chain, cached_macro_block_header):
    print('parentless')
    flag = 1
    if len(cached_macro_block_header) != 0:
        while flag > 0:
            for i in cached_macro_block_header:
                if i.hash in macro_chain.accepted_macro_block_headers.keys():
                    del macro_chain.accepted_macro_block_headers[i.hash]
                result = macro_chain.add_macro_block_header(i)
                if result:
                    cached_macro_block_header.remove(i)
                    i_ = 0
                    for index, j in enumerate(macro_chain.chain_.queue):
                        if j.hash == i.hash:
                            i_ = index
                            break
                    for k in range(len(macro_chain.chain_.queue) - i_):
                        if macro_chain.chain_.queue[i_ + k].hash in \
                                macro_chain.ref_micro_block.keys():
                            for q in (macro_chain.ref_micro_block[macro_chain.chain_.
                                      queue[i_ + k].hash]):
                                trans_retrieve(q, macro_chain)
                    for k in range(len(macro_chain.chain_.queue) - i_):
                        if macro_chain.chain_.queue[i_ + k].hash in \
                                macro_chain.ref_micro_block.keys():
                            macro_chain.add_trans(macro_chain.chain_.queue[i_ + k].hash)

                    if len(cached_macro_block_header) == 0:
                        flag = 0
                    else:
                        flag = 1
                    break
                flag = 0


def ass_func_for_pbp(macro_block_header, ass_chain):
    for i in ass_chain:
        if macro_block_header.previous_hash == i.hash:
            ass_chain[macro_block_header] = (1, i)
            return True
    return False


def parentless_macro_block_body_process(macro_block_body: MacroBlockBody, macro_chain):
    if macro_block_body.hash in macro_chain.accepted_macro_block_bodies.keys():
        del macro_chain.accepted_macro_block_bodies[macro_block_body.hash]
        processor_macro_block_body_write(macro_block_body.b, macro_chain, cached_macro_block_body,
                                         cached_macro_block_header, ass_macro_chain)


private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
public_key = private_key.public_key()
sy = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
sha = hashlib.sha256()
sha.update(sy)
public_key_hash = sha.digest()

ass_macro_chain = dict()
cached_macro_block_body = list()
cached_macro_block_header = list()
macro_chain = MacroChain()


macro_block_header1 = MacroBlockHeader(0, 1, public_key_hash, [INIT_HASH], 0)

macro_block_body1 = MacroBlockBody(macro_block_header1.hash, [block1.hash], trans1)
macro_block_body1.ready(private_key)


macro_block_header2 = MacroBlockHeader(0, 2, public_key_hash, [macro_block_header1.hash], 0)

macro_block_body2 = MacroBlockBody(macro_block_header2.hash, [block2.hash], trans1)
macro_block_body2.ready(private_key)

macro_block_header3 = MacroBlockHeader(0, 3, public_key_hash, [macro_block_header2.hash], 0)

macro_block_body3 = MacroBlockBody(macro_block_header3.hash, [block3.hash], trans1)
macro_block_body3.ready(private_key)

macro_block_header4 = MacroBlockHeader(0, 4, public_key_hash, [macro_block_header3.hash], 0)

macro_block_body4 = MacroBlockBody(macro_block_header4.hash, [block6.hash], trans1)
macro_block_body4.ready(private_key)

macro_block_header5 = MacroBlockHeader(0, 5, public_key_hash, [macro_block_header4.hash], 0)

macro_block_body5 = MacroBlockBody(macro_block_header5.hash, [block4.hash], trans1)
macro_block_body5.ready(private_key)

macro_block_header8 = MacroBlockHeader(0, 8, public_key_hash, [macro_block_header5.hash], 0)

macro_block_body8 = MacroBlockBody(macro_block_header8.hash, [block8.hash], trans1)
macro_block_body8.ready(private_key)

macro_block_header6 = MacroBlockHeader(0, 6, public_key_hash, [macro_block_header4.hash], 0)

macro_block_body6 = MacroBlockBody(macro_block_header6.hash, [], trans1)
macro_block_body6.ready(private_key)

macro_block_header7 = MacroBlockHeader(0, 7, public_key_hash, [macro_block_header4.hash], 0)

macro_block_body7 = MacroBlockBody(macro_block_header7.hash, [block7.hash], trans1)
macro_block_body7.ready(private_key)

macro_block_header9 = MacroBlockHeader(0, 9, public_key_hash, [macro_block_header6.hash], 0)

macro_block_body9 = MacroBlockBody(macro_block_header9.hash, [block5.hash], trans1)
macro_block_body9.ready(private_key)

macro_block_header10 = MacroBlockHeader(0, 10, public_key_hash, [macro_block_header9.hash], 0)

macro_block_body10 = MacroBlockBody(macro_block_header10.hash, [block9.hash], trans1)
macro_block_body10.ready(private_key)


macro_chain.accepted_macro_block_headers[macro_block_header.hash] = 1
macro_chain.accepted_macro_block_headers[macro_block_header1.hash] = 1
macro_chain.accepted_macro_block_headers[macro_block_header2.hash] = 1
macro_chain.accepted_macro_block_headers[macro_block_header3.hash] = 1
macro_chain.accepted_macro_block_headers[macro_block_header4.hash] = 1
macro_chain.accepted_macro_block_headers[macro_block_header5.hash] = 1
macro_chain.accepted_macro_block_headers[macro_block_header6.hash] = 1
macro_chain.accepted_macro_block_headers[macro_block_header7.hash] = 1
macro_chain.accepted_macro_block_headers[macro_block_header8.hash] = 1
macro_chain.accepted_macro_block_headers[macro_block_header9.hash] = 1
macro_chain.accepted_macro_block_headers[macro_block_header10.hash] = 1

macro_chain.accepted_macro_block_header_hash.append(macro_block_header1.hash)
macro_chain.accepted_macro_block_header_hash.append(macro_block_header2.hash)
macro_chain.accepted_macro_block_header_hash.append(macro_block_header3.hash)
macro_chain.accepted_macro_block_header_hash.append(macro_block_header4.hash)
macro_chain.accepted_macro_block_header_hash.append(macro_block_header5.hash)
macro_chain.accepted_macro_block_header_hash.append(macro_block_header8.hash)
macro_chain.accepted_micro_blocks[block1.hash] = 1
macro_chain.accepted_micro_blocks[block2.hash] = 1
macro_chain.accepted_micro_blocks[block3.hash] = 1
macro_chain.accepted_micro_blocks[block4.hash] = 1
macro_chain.accepted_micro_blocks[block5.hash] = 1
macro_chain.accepted_micro_blocks[block6.hash] = 1
macro_chain.accepted_micro_blocks[block7.hash] = 1
macro_chain.accepted_micro_blocks[block8.hash] = 1
macro_chain.accepted_micro_blocks[block9.hash] = 1
macro_chain.utxo.add(block1.data.trans[0])
macro_chain.utxo_two.add_two(block1.data.trans[0], macro_block_header1.hash)

macro_chain.length = 7
for i in macro_chain.chain_.queue:
    print(i.timestamp)

for i in ass_macro_chain.items():
    print(i[0].timestamp, i[1][1].timestamp)

print(macro_chain.utxo.utxo.items())
macro_chain.micro_block_pool.append(block)
macro_chain.micro_block_pool.append(block1)
macro_chain.micro_block_pool.append(block2)
macro_chain.micro_block_pool.append(block3)
macro_chain.micro_block_pool.append(block4)
macro_chain.micro_block_pool.append(block5)
macro_chain.micro_block_pool.append(block6)
macro_chain.micro_block_pool.append(block7)
macro_chain.micro_block_pool.append(block8)
macro_chain.micro_block_pool.append(block9)

macro_chain.chain_.put(macro_block_header1)
processor_macro_block_body_write(macro_block_body1.b, macro_chain, cached_macro_block_body, cached_macro_block_header,
                                 ass_macro_chain)
macro_chain.chain_.put(macro_block_header2)
print('\n')
processor_macro_block_body_write(macro_block_body2.b, macro_chain, cached_macro_block_body, cached_macro_block_header,
                                 ass_macro_chain)
print('\n')
macro_chain.chain_.put(macro_block_header3)
processor_macro_block_body_write(macro_block_body3.b, macro_chain, cached_macro_block_body, cached_macro_block_header,
                                 ass_macro_chain)
print('\n')

print('33333')
processor_macro_block_body_write(macro_block_body5.b, macro_chain, cached_macro_block_body, cached_macro_block_header,
                                 ass_macro_chain)
print('444444')
processor_macro_block_body_write(macro_block_body4.b, macro_chain, cached_macro_block_body, cached_macro_block_header,
                                 ass_macro_chain)
print('\n')
print(cached_macro_block_body)
# macro_chain.chain_.put(macro_block_header5)
cached_macro_block_header.append(macro_block_header5)
cached_macro_block_header.append(macro_block_header4)

print('parentless macro_block_header process')
parentless_macro_block_header_process(macro_chain, cached_macro_block_header)
print('parentless macro_block_header process finished')
print('iiiiiii')
# processor_macro_block_body_write(macro_block_body4.b, macro_chain, cached_macro_block_body, cached_macro_block_header,
#                                  ass_macro_chain)

print('ok ok  ok\n')
parentless_macro_block_body_process(macro_block_body5, macro_chain)
print('ok kk\n')

parentless_macro_block_body_process(macro_block_body4, macro_chain)
print('\nzero')
macro_chain.chain_.put(macro_block_header8)
ass_macro_chain[macro_block_header6] = (0, macro_block_header4)
ass_macro_chain[macro_block_header7] = (0, macro_block_header4)
ass_macro_chain[macro_block_header9] = (1, macro_block_header6)
ass_macro_chain[macro_block_header10] = (1, macro_block_header9)
processor_macro_block_body_write(macro_block_body6.b, macro_chain, cached_macro_block_body, cached_macro_block_header,
                                 ass_macro_chain)
processor_macro_block_body_write(macro_block_body7.b, macro_chain, cached_macro_block_body, cached_macro_block_header,
                                 ass_macro_chain)
processor_macro_block_body_write(macro_block_body8.b, macro_chain, cached_macro_block_body, cached_macro_block_header,
                                 ass_macro_chain)
processor_macro_block_body_write(macro_block_body9.b, macro_chain, cached_macro_block_body, cached_macro_block_header,
                                 ass_macro_chain)
processor_macro_block_body_write(macro_block_body10.b, macro_chain, cached_macro_block_body, cached_macro_block_header,
                                 ass_macro_chain)

print(macro_block_body1.show_macro_block_body())


print('utxo=', macro_chain.utxo.utxo.items())
# for i in macro_chain.chain_.queue:
#     print(i.timestamp)

# longest_chain(ass_macro_chain, macro_chain, macro_block_header10)
# for i in ass_macro_chain.items():
#     print(i[0].timestamp, i[1][1].timestamp)

print(macro_chain.utxo.utxo)


print('\n\ncomprehensive test for DAG blockchain structure\n\n')

test = dict()
test[b'G'] = [b'A', b'B']
test[b'A'] = [b'C']
test[b'E'] = []
test[b'C'] = [b'D', b'E']
test[b'D'] = []

print(test.items())
fd = open('DAG_structure.txt', 'w')
fd.writelines(str(6) + ' ')
fd.writelines(str(b'G') + '\n')
for i in test.items():
    if len(i[1]) > 0:
        for i_ in i[1]:
            fd.writelines(str(i[0]) + ' ')
            fd.writelines(str(i_) + '\n')
fd.close()

a = dict()
a[1] = [22, 44]
a[22] = [44]
for i in a:
    print(i)
print(a.keys())
for index, i in enumerate(a.keys()):
    print(i)


def io_operations(test):
    fd_ = open('DAG_structure.txt', 'w')
    fd_.writelines(str(b'G') + '\n')
    for i in test.items():
        if len(i[1]) > 0:
            for i_ in i[1]:
                fd_.writelines(str(i[0]) + ' ')
                fd_.writelines(str(i_) + '\n')
    fd_.close()


io_operations(test)
chain = queue.Queue()


def out_operations():
    fd_ = open('DAG.txt', 'r')
    for index, line in enumerate(fd_.readlines()):
        if index == 0:
            pass
        else:
            chain.put(bytes(line.rstrip()[2:-1], encoding='utf-8'))
    fd_.close()


out_operations()
for i in chain.queue:
    print(i, type(i))

a = [1, 4, 5]
print(min(a))

for index, i in enumerate(a):
    print(i)
    if 4 >= i:
        pass
    else:
        print(index)
        a.insert(index, 4)
        break

print('ok', a)

a = [1, 3, 4, 6, 7]
b = [1]

flag = 1
l = min(5, 1)
i = 0
while flag == 1:
    if i < l:
        if a[i] == b[i]:
            i += 1
        else:
            flag = 0
    else:
        flag = 0
print(i)
for i in range(4):
    print('ok', i)

a = queue.Queue()
a.put(2)
a.put(3)
a.put(5)
a.put(7)
print(a.queue)
a.queue.pop()
print(a.queue)
k = 0
for k in range(5):
    if k == 2:
        break
print(k)
z = 0
for z in blockchain_test.chain.queue:
    pass
print(z.show_block())
content = INIT_HASH + INIT_HASH + INIT_HASH
print(content)
result = list()
len_ = int(len(content) / 32)
for i in range(len_):
    result.append(content[i * 32:(i + 1) * 32])

for i in result:
    print(i)


a = str(INIT_HASH) + '\n'
print(a)
c = bytes(a.rstrip()[2:-1], encoding='utf-8')
c = codecs.escape_decode(c, 'hex-escape')[0]
a = INIT_HASH
c = codecs.escape_encode(a)[0]
print(c)
print(type(c))
c = codecs.escape_decode(c)[0]
print(c)

a = '\34324234243'
print(type(a))
c = codecs.escape_decode(a)[0]
print(c)

print(type(str(INIT_HASH)))
print(codecs.escape_decode(str(INIT_HASH).rstrip()[2:-1], 'hex-escape')[0])
q = str(b"`A\xaby\xc6\xa0Kx+\x06\x95\x98\x1dSR\xcc\x01\x1e4\xfdC\xe1-$''\xb7j<\x8f\x1ck")
q = bytes(q.rstrip()[2:-1], encoding='utf-8')
q = codecs.escape_decode(q, 'hex-escape')[0]
print(q)


def out_operations():
    fd_ = open('DAG_test_two.txt', 'r')
    for index, line in enumerate(fd_.readlines()):
        if index == 0:
            pass
        else:
            print(line)
            temp = bytes(line.rstrip()[2:-1], encoding='utf-8')
            temp = codecs.escape_decode(temp)[0]
            print(temp)
    fd_.close()


print('\n in')
out_operations()

a = b'\xdbX\x1a\xfdT\xe8\xaaQ\x00^\xaa\xc2 @\xd2\xfc\xde1\xf3M\x7f\xda\x04D\xc3\xfc\xd3\xe7\xc9\xbbO\xc6'
a = str(a.replace(b' ', b'ECS')) + '\n'
temp = bytes(a.rstrip()[2:-1], encoding='utf-8')
temp = temp.replace(b'ECS', b' ')
temp = codecs.escape_decode(temp)[0]
print(temp)