# -*- coding: utf-8 -*-
"""
    block_test
    ~~~~~~~~~~

    general test of blockchain functions

    :author: hank
"""

import unittest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import hashlib
from source import blockchain
import time
import struct


class BlockChainTestCase(unittest.TestCase):
    def setUp(self):
        self.private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
        self.public_key = self.private_key.public_key()
        self.public_key = self.public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        sha = hashlib.sha256()
        sha.update(self.public_key)
        self.public_key_hash = sha.digest()
        tinput = [
            (b'4', 1),
            (b'3', 2),
            (b'2', 3),
            (b'1', 4)
        ]
        self.T1 = blockchain.TransInput(tinput, self.public_key_hash)

        public_key_hash = []
        for i in range(5):
            private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
            public_key = private_key.public_key()
            public_key = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            sha = hashlib.sha256()
            sha.update(public_key)
            public_key_hash.append(sha.digest())
        self.public_key_hash_list = public_key_hash
        from random import randint
        toutput = [(randint(0, 10240), public_key_hash[i]) for i in range(5)]
        self.T2 = blockchain.TransOutput(toutput)
        self.T3 = blockchain.Transaction(self.T1, self.T2)

    def test_000_trans_input_build(self):
        T = self.T1
        self.assertEqual(T[3][0], b'1')
        self.assertEqual(T[1][1], 2)
        self.assertEqual(T.b[-32:], self.public_key_hash)
        self.assertEqual(len(T.b), 52)

    def test_001_trans_output_build(self):
        T = self.T2
        self.assertEqual(T[2][1], self.public_key_hash_list[2])
        self.assertEqual(len(T.b), 5 * 40)

    def test_002_transaction_build(self):
        T = self.T3
        self.assertEqual(T.public_key, None)
        self.assertEqual(T.signature, None)
        self.assertEqual(T.timestamp, None)
        self.assertEqual(T.txid, None)
        self.assertEqual(len(T.b), 0)
        self.assertEqual(T.version, 1)

        T.ready(self.private_key)
        self.assertNotEqual(T.public_key, None)
        self.assertNotEqual(T.signature, None)
        self.assertNotEqual(T.timestamp, None)
        self.assertNotEqual(T.txid, None)
        self.assertGreater(len(T.b), 0)
        self.assertEqual(T.version, 1)

    def test_003_block_build(self):
        self.T3.ready(self.private_key)
        at = blockchain.Attachment()
        at.add_data(b'I am the king of the kings')
        at.ready()
        bd = blockchain.BlockData([self.T3, self.T3], at)
        block = blockchain.Block(0, time.time(), bd, bytes(32), 33)
        self.assertGreater(len(block.b), 0)

    def test_004_trans_input_rebuild(self):
        private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
        public_key = private_key.public_key()
        public_key = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        sha = hashlib.sha256()
        sha.update(public_key)
        public_key_hash = sha.digest()
        tinput = [
            (bytes(32), 1),
            (bytes(32), 2),
            (public_key_hash, 3),
            (public_key_hash, 4)
        ]
        T1 = blockchain.TransInput(tinput, public_key_hash)
        T1_copy = blockchain.TransInput.unpack(T1.b)
        self.assertEqual(T1_copy.b, T1.b)
        self.assertEqual(T1_copy.content, T1.content)
        self.assertEqual(T1_copy.public_key_hash, T1.public_key_hash)

    def test_005_trans_output_rebuild(self):
        T2_copy = blockchain.TransOutput.unpack(self.T2.b)
        self.assertEqual(T2_copy.b, self.T2.b)
        self.assertEqual(T2_copy.content, self.T2.content)

    def test_006_transaction_rebuild(self):
        private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
        public_key = private_key.public_key()
        public_key = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        sha = hashlib.sha256()
        sha.update(public_key)
        public_key_hash = sha.digest()
        tinput = [
            (bytes(32), 1),
            (bytes(32), 2),
            (public_key_hash, 3),
            (public_key_hash, 4)
        ]
        T1 = blockchain.TransInput(tinput, public_key_hash)

        public_key_hash = []
        for i in range(5):
            private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
            public_key = private_key.public_key()
            public_key = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            sha = hashlib.sha256()
            sha.update(public_key)
            public_key_hash.append(sha.digest())
        from random import randint
        toutput = [(randint(0, 10240), public_key_hash[i]) for i in range(5)]
        T2 = blockchain.TransOutput(toutput)

        T = blockchain.Transaction(T1, T2)
        T.ready(private_key)
        T_copy = blockchain.Transaction.unpack(T.b)
        self.assertEqual(T_copy.version, T.version)
        self.assertEqual(T_copy.b, T.b)
        # self.assertEqual(T_copy.public_key, T.public_key)
        self.assertEqual(T_copy.timestamp, T.timestamp)

        T_copy.public_key.verify(T_copy.signature,
                                 struct.pack('=f', T_copy.timestamp) + T_copy.ipt.b + T_copy.opt.b,
                                 ec.ECDSA(hashes.SHA256()))

        self.assertEqual(T_copy.signature, T.signature)
        self.assertEqual(T_copy.txid, T.txid)
        self.assertEqual(T_copy.ipt.b, T.ipt.b)
        self.assertEqual(T_copy.opt.b, T.opt.b)

    def test_007_attachment_rebuild(self):
        at = blockchain.Attachment()
        at.add_data(b'i am the king of kings')
        at.ready()

        at_copy = blockchain.Attachment.unpack(at.b)
        self.assertEqual(at.content, at_copy.content)

    def test_008_blockdata_rebuild(self):
        private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
        public_key = private_key.public_key()
        public_key = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        sha = hashlib.sha256()
        sha.update(public_key)
        public_key_hash = sha.digest()
        tinput = [
            (bytes(32), 1),
            (bytes(32), 2),
            (public_key_hash, 3),
            (public_key_hash, 4)
        ]
        T1 = blockchain.TransInput(tinput, public_key_hash)

        public_key_hash = []
        for i in range(5):
            private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
            public_key = private_key.public_key()
            public_key = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            sha = hashlib.sha256()
            sha.update(public_key)
            public_key_hash.append(sha.digest())
        from random import randint
        toutput = [(randint(0, 10240), public_key_hash[i]) for i in range(5)]
        T2 = blockchain.TransOutput(toutput)

        T = blockchain.Transaction(T1, T2)
        T.ready(private_key)

        at = blockchain.Attachment()
        at.add_data(b'I am the king of the kings')
        at.ready()

        bd = blockchain.BlockData([T, T], at)
        bd_copy = blockchain.BlockData.unpack(bd.b)

        self.assertEqual(bd_copy.trans[0].version, bd.trans[0].version)
        self.assertEqual(bd_copy.trans[0].b, bd.trans[0].b)
        # self.assertEqual(T_copy.public_key, T.public_key)
        self.assertEqual(bd_copy.trans[0].timestamp, bd.trans[0].timestamp)

        bd_copy.trans[0].public_key.verify(bd_copy.trans[0].signature,
                                           struct.pack('=f', bd_copy.trans[0].timestamp) +
                                           bd_copy.trans[0].ipt.b + bd_copy.trans[0].opt.b,
                                           ec.ECDSA(hashes.SHA256()))

        self.assertEqual(bd_copy.trans[0].signature, bd.trans[0].signature)
        self.assertEqual(bd_copy.trans[0].txid, bd.trans[0].txid)
        self.assertEqual(bd_copy.trans[0].ipt.b, bd.trans[0].ipt.b)
        self.assertEqual(bd_copy.trans[0].opt.b, bd.trans[0].opt.b)

        self.assertEqual(bd_copy.trans[1].version, bd.trans[1].version)
        self.assertEqual(bd_copy.trans[1].b, bd.trans[1].b)
        # self.assertEqual(T_copy.public_key, T.public_key)
        self.assertEqual(bd_copy.trans[1].timestamp, bd.trans[1].timestamp)

        bd_copy.trans[1].public_key.verify(bd_copy.trans[1].signature,
                                           struct.pack('=f', bd_copy.trans[1].timestamp) +
                                           bd_copy.trans[1].ipt.b + bd_copy.trans[1].opt.b,
                                           ec.ECDSA(hashes.SHA256()))

        self.assertEqual(bd_copy.trans[1].signature, bd.trans[1].signature)
        self.assertEqual(bd_copy.trans[1].txid, bd.trans[1].txid)
        self.assertEqual(bd_copy.trans[1].ipt.b, bd.trans[1].ipt.b)
        self.assertEqual(bd_copy.trans[1].opt.b, bd.trans[1].opt.b)

        self.assertEqual(bd_copy.trans[1].version, bd.trans[1].version)
        self.assertEqual(bd_copy.trans[1].b, bd.trans[1].b)

        self.assertEqual(bd_copy.b, bd.b)
        self.assertEqual(bd_copy.attachment.content, bd.attachment.content)

    def test_009_block_rebuild(self):
        private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
        public_key = private_key.public_key()
        public_key = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        sha = hashlib.sha256()
        sha.update(public_key)
        public_key_hash = sha.digest()
        tinput = [
            (bytes(32), 1),
            (bytes(32), 2),
            (public_key_hash, 3),
            (public_key_hash, 4)
        ]
        T1 = blockchain.TransInput(tinput, public_key_hash)

        public_key_hash = []
        for i in range(5):
            private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
            public_key = private_key.public_key()
            public_key = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            sha = hashlib.sha256()
            sha.update(public_key)
            public_key_hash.append(sha.digest())
        from random import randint
        toutput = [(randint(0, 10240), public_key_hash[i]) for i in range(5)]
        T2 = blockchain.TransOutput(toutput)

        T = blockchain.Transaction(T1, T2)
        T.ready(private_key)

        at = blockchain.Attachment()
        at.add_data(b'I am the king of the kings')
        at.ready()

        bd = blockchain.BlockData([T], at)
        block = blockchain.Block(0, time.time(), bd, bytes(32), 33)
        block_copy = blockchain.Block.unpack(block.b)

        self.assertEqual(block.b, block_copy.b)
        self.assertEqual(block.hash, block_copy.hash)
        self.assertEqual(block.previous_hash, block_copy.previous_hash)
        self.assertEqual(block.timestamp, block_copy.timestamp)
        self.assertEqual(block.index, block_copy.index)
        self.assertEqual(block.data.attachment.content, block_copy.data.attachment.content)
        self.assertEqual(block.nonce, block_copy.nonce)

    def test_010_block_search(self):
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
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

        tinput = [
            (b'O\x1e,-\xe1\xa0!\x16D\x87\xcc\x923\xf7\xf6\xca\xad\xd1\t\x8eV\xdc\xe8t}N\xfa\x8af\xbe\xe7\xef', 0)
        ]
        T1 = blockchain.TransInput(tinput, public_key_hash)

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
        T2 = blockchain.TransOutput(toutput)

        T = blockchain.Transaction(T1, T2)
        T.ready(private_key1)

        at = blockchain.Attachment()
        at.add_data(b'latex')
        at.ready()

        bd = blockchain.BlockData([T], at)
        t = time.time()
        block = blockchain.Block(1, t, bd, bytes(32), 33)
        chain = blockchain.Blockchain()
        block.previous_hash = chain.chain.queue[0].hash
        chain.add_block(block)
        block1 = chain.search_block(index=1)
        self.assertEqual(block1.data.attachment.content, b'latex')
        block1 = chain.search_block(hash=block.hash)
        self.assertEqual(block1.data.attachment.content, b'latex')
        block1 = chain.search_block(timestamp=t)
        self.assertEqual(block1.data.attachment.content, b'latex')

    def test_011_UTXOTABLE(self):
        private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
        public_key = private_key.public_key()
        public_key = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        sha = hashlib.sha256()
        sha.update(public_key)
        public_key_hash = sha.digest()
        tinput = [
            (bytes(32), 1),
            (bytes(32), 2),
            (public_key_hash, 3),
            (public_key_hash, 4)
        ]
        T1 = blockchain.TransInput(tinput, public_key_hash)

        public_key_hash = []
        for i in range(5):
            private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
            public_key = private_key.public_key()
            public_key = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            sha = hashlib.sha256()
            sha.update(public_key)
            public_key_hash.append(sha.digest())
        from random import randint
        toutput = [(randint(0, 10240), public_key_hash[i]) for i in range(5)]
        T2 = blockchain.TransOutput(toutput)

        T = blockchain.Transaction(T1, T2)
        T.ready(private_key)

        from source.blockchain import UTXOTable
        table = UTXOTable()
        table.add(T)
        table.info((T.txid, 4))
        table.info((T.txid, 3))
        self.assertTrue(table.check((T.txid, 4), T.opt[4][0], T.opt[4][1]))
        self.assertFalse(table.check((T.txid, 3), T.opt[4][0], T.opt[4][1]))
        self.assertFalse(table.check((T.txid, 6), T.opt[4][0], T.opt[4][1]))


if __name__ == '__main__':
    unittest.main(verbosity=2)
