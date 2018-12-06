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

fd_ = open('ad1.txt', 'r')
public_key = b''
private_key = b''
for index, line in enumerate(fd_.readlines()):
    if index == 0:
        line = line.rstrip()
        pr, pu = line.split('ENDDING')
        temp = bytes(pr[2:-1], encoding='utf-8')
        temp = temp.replace(b'\r\n', b'\n')
        private_key = temp.replace(b'\\n', b'\n')
        temp = bytes(pu[2:-1], encoding='utf-8')
        temp = temp.replace(b'\r\n', b'\n')
        public_key = temp.replace(b'\\n', b'\n')
        break
fd_.close()

sha = hashlib.sha256()
sha.update(public_key)
public_key_hash = sha.digest()

macro_chain = MacroChain()
macro_chain.accepted_macro_block_headers[INIT_HASH] = 1
macro_block_header = MacroBlockHeader(0, 0, public_key_hash, [], 0)
macro_block_header.hash = INIT_HASH
macro_chain.chain_.put(macro_block_header)
macro_block_header1 = MacroBlockHeader(0, 11.1111, public_key_hash, [INIT_HASH], 0)

