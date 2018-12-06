# -*- coding: utf-8 -*-
"""
    block_test
    ~~~~~~~~~~

    general test of chain services

    :author: hank
"""
import socket
import unittest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key
import hashlib
import time
import struct

from source.blockchain import TransInput, TransOutput, Transaction, BlockData, Block, Attachment
from source.transfer import send_handler, batch_parser, MsgType, recv_parser


class BlockChainTestCase(unittest.TestCase):
    def setUp(self):
        import random
        self.address = (r'/tmp/chainbase0.2968406540984335')

    def test_000_trans_write(self):
        """
        The first (genesis) block contains a transaction that pays 42 to the address that corresponds to the
        following private key. This test case first use this private key to issue and submit a transaction
        which pays 7 for 6 random addresses. This transaction is valid and stays in the pool of transactions.
        Then the test try to issue a new transaction. Because the 42 assets of the following private key were
        used up, the new transaction is invalid. Finally, the test pays 7 from random address 1 to address 2.
        """

        tinput = [
            (b'O\x1e,-\xe1\xa0!\x16D\x87\xcc\x923\xf7\xf6\xca\xad\xd1\t\x8eV\xdc\xe8t}N\xfa\x8af\xbe\xe7\xef', 0)
        ]

        private_key1 = load_pem_private_key(b'-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0w'
                                            b'awIBAQQg64DiDBUkuGC5rrTfH6uy\nHt6vhvHrMHj3Gm64SZtdqtKhRANCAATMIea'
                                            b'IK4vT0ni00F6GGW40qioinPFgXjsj\n6sZGivW9Ipj+zcDfPc7RxZuFeKFmbtVaUX'
                                            b'Z877DM4C8ELZs2DPVQ\n-----END PRIVATE KEY-----\n',
                                           None, default_backend())
        public_key = b'-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEzCHmiCuL09J4tNBehhluNKoqIpzx' \
                     b'YF47\nI+rGRor1vSKY/s3A3z3O0cWbhXihZm7VWlF2fO+wzOAvBC2bNgz1UA==\n-----END PUBLIC KEY-----\n'
        sha = hashlib.sha256()
        sha.update(public_key)
        public_key_hash = sha.digest()


        T1 = TransInput(tinput, public_key_hash)

        public_key_hash = []
        private_keys = []
        public_keys = []

        for i in range(6):
            private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
            private_keys.append(private_key)

            public_key = private_key.public_key()
            public_key = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            public_keys.append(public_key)

            sha = hashlib.sha256()
            sha.update(public_key)
            public_key_hash.append(sha.digest())

        toutput = [(7, public_key_hash[i]) for i in range(6)]
        T2 = TransOutput(toutput)

        T = Transaction(T1, T2)
        T.ready(private_key1)

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:  # submit the valid transaction

            s.connect(self.address)
            payload = send_handler(MsgType.TYPE_TRANS_WRITE, T.b)
            s.sendall(payload)
            header, length, msgtype, content = recv_parser(s)

            self.assertEqual(content, b'')
            self.assertEqual(length, 0)
            self.assertEqual(msgtype, MsgType.TYPE_RESPONSE_OK)  # the chainbase returns OK

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            # submit the same transaction, but it is invalid this time

            s.connect(self.address)
            payload = send_handler(MsgType.TYPE_TRANS_WRITE, T.b)
            s.sendall(payload)
            header, length, msgtype, content = recv_parser(s)

            self.assertEqual(content, b'')
            self.assertEqual(length, 0)
            self.assertEqual(msgtype, MsgType.TYPE_RESPONSE_ERROR)  # the chainbase returns ERROR

        """
        construct a second valid transaction, which pay 7 from random address 1 to random address 2
        """
        private_key = private_keys[0]
        public_key = public_keys[0]
        public_key_hash1 = public_key_hash[0]

        T1 = TransInput([(T.txid, 0)], public_key_hash1)

        toutput = [(7, public_key_hash[1])]
        T2 = TransOutput(toutput)

        T = Transaction(T1, T2)
        T.ready(private_key)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:  # submit the second valid transaction

            s.connect(self.address)
            payload = send_handler(MsgType.TYPE_TRANS_WRITE, T.b)
            s.sendall(payload)
            header, length, msgtype, content = recv_parser(s)

            self.assertEqual(content, b'')
            self.assertEqual(length, 0)
            self.assertEqual(msgtype, MsgType.TYPE_RESPONSE_OK)  # the chainbase returns OK

    def test_001_block_write(self):
        """
        use the same case as the test_000_trans_write, but transactions are seperated into different blocks
        :return:
        """
        # replace the following connection address with the address in the chainbase



        tinput = [
            (b'O\x1e,-\xe1\xa0!\x16D\x87\xcc\x923\xf7\xf6\xca\xad\xd1\t\x8eV\xdc\xe8t}N\xfa\x8af\xbe\xe7\xef', 0)
        ]

        private_key1 = load_pem_private_key(b'-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0w'
                                            b'awIBAQQg64DiDBUkuGC5rrTfH6uy\nHt6vhvHrMHj3Gm64SZtdqtKhRANCAATMIea'
                                            b'IK4vT0ni00F6GGW40qioinPFgXjsj\n6sZGivW9Ipj+zcDfPc7RxZuFeKFmbtVaUX'
                                            b'Z877DM4C8ELZs2DPVQ\n-----END PRIVATE KEY-----\n',
                                           None, default_backend())
        public_key = b'-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEzCHmiCuL09J4tNBehhluNKoqIpzx' \
                     b'YF47\nI+rGRor1vSKY/s3A3z3O0cWbhXihZm7VWlF2fO+wzOAvBC2bNgz1UA==\n-----END PUBLIC KEY-----\n'
        sha = hashlib.sha256()
        sha.update(public_key)
        public_key_hash = sha.digest()


        T1 = TransInput(tinput, public_key_hash)

        public_key_hash = []
        private_keys = []
        public_keys = []

        for i in range(6):
            private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
            private_keys.append(private_key)

            public_key = private_key.public_key()
            public_key = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            public_keys.append(public_key)

            sha = hashlib.sha256()
            sha.update(public_key)
            public_key_hash.append(sha.digest())

        toutput = [(7, public_key_hash[i]) for i in range(6)]
        T2 = TransOutput(toutput)

        T = Transaction(T1, T2)
        T.ready(private_key1)

        pri_key = private_keys[0]
        public_key_hash1 = public_key_hash[0]

        T8 = TransInput([(T.txid, 0)], public_key_hash1)

        toutput = [(7, public_key_hash[1])]
        T9 = TransOutput(toutput)

        T4 = Transaction(T8, T9)
        T4.ready(pri_key)

        at = Attachment()
        at.add_data(b'')
        at.ready()

        bd = BlockData([T, T4], at)
        t = time.time()
        block = Block(1,
                      t,
                      bd,
                      b'G\xfdk\x88\xda5\xff\x8c\x97t\x9f\xcb\xe0\xa8\x07S\x8b9t:.9\x1d\xee\xf4\xb1\xda\xd1r\xaf\xfcu',
                      33)

        """
        construct a second valid transaction, which pay 7 from random address 1 to random address 2 
        """

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:  # submit the second valid transaction

            s.connect(self.address)
            payload = send_handler(MsgType.TYPE_BLOCK_WRITE, block.b)
            s.sendall(payload)
            header, length, msgtype, content = recv_parser(s)

            self.assertEqual(content, b'')
            self.assertEqual(length, 0)
            self.assertEqual(msgtype, MsgType.TYPE_RESPONSE_OK)  # the chainbase returns OK

    def test_002_trans_read(self):

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.address)
            s.sendall(send_handler(MsgType.TYPE_TRANS_READ, b''))
            header, length, msgtype, content = recv_parser(s)
            content = batch_parser(content)


            for i in content:
                Transaction.unpack(i)
            self.assertEqual(msgtype, MsgType.TYPE_RESPONSE_OK)
            self.assertEqual(len(content), 2)

    def test_003_trans_retrieve(self):

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.address)
            s.sendall(send_handler(MsgType.TYPE_TRANS_RETRIEVE, struct.pack('=i', 1)))
            header, length, msgtype, content = recv_parser(s)
            content = batch_parser(content)


            for i in content:
                Transaction.unpack(i)
            self.assertEqual(msgtype, MsgType.TYPE_RESPONSE_OK)
            self.assertEqual(len(content), 1)

    def test_004_previous_hash(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.address)
            s.sendall(send_handler(MsgType.TYPE_BLOCK_PREVIOUS_HASH, b''))
            header, length, msgtype, content = recv_parser(s)

            self.assertEqual(msgtype, MsgType.TYPE_RESPONSE_OK)
            self.assertEqual(len(content), 32)
            print(content)