# -*- coding: utf-8 -*-
"""
    chainbase
    ~~~~~~~~~

    Implements backend of blockchain

    :author: hank
"""

from source.blockchain import Blockchain, Block, TransPool, LightBlock, BlockData, TransOutput, \
    TransInput, Transaction
from source.transfer import MsgType, recv_parser, send_handler, batch_handler, batch_parser
from source.errors import *
from source.utility import bin2int
from source.Trans import trans_to_json
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import socketserver
import random
import sys
import struct
import time
import requests


class ChainMsgHandler(socketserver.StreamRequestHandler):

    def handle(self):
        """
        handle messages from webchain and conchain
        :return: None
        """

        handlers = {
            # write the submitted transaction to the transpool
            MsgType.TYPE_TRANS_WRITE: self.processor_trans_write,

            # provide transactions in the transpool
            MsgType.TYPE_TRANS_READ: self.processor_trans_read,

            # write the submitted block (the result of consensus) to the blockchain
            MsgType.TYPE_BLOCK_WRITE: self.processor_block_write,

            # convert the lightblock to normal block and write it to the blockchain
            MsgType.TYPE_LIGHTBLOCK_WRITE: self.processor_lightblock_write,

            # search the transaction that has the given txid
            MsgType.TYPE_TRANS_SEARCH_TXID: self.processor_trans_search_txid,

            # return the previous hash for constructing nonce
            MsgType.TYPE_BLOCK_PREVIOUS_HASH: self.processor_prev_hash,

            # send back blocks whose indexes locate in [start, end]
            MsgType.TYPE_BLOCK_READ: self.processor_block_read,

            # create Trans
            MsgType.TYPE_TRANS_MAKE: self.processor_trans_make,

            # get miner's credit
            MsgType.TYPE_MINER_CREDIT: self.processor_miner_credit
        }

        *_, msgtype, content = recv_parser(self.request)

        handlers[msgtype](content)

    def processor_trans_write(self, content):
        # print('ok3')
        result = self.server.transpool.add(content)
        tran = Transaction.unpack(content)
        # print(tran.show_trans())
        if result:
            # a = Transaction.unpack(content)
            _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')
            # print('trans_received')
            # print(a.timestamp)
            # print(time.time())
            # print(len(self.server.transpool.trans.queue))
        else:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

        self.request.sendall(_)

    def processor_miner_credit(self, content):
        info = batch_parser(content)
        if info[0] in self.server.Address.keys():
            self.server.Address[info[0]][0] += struct.unpack('=d', info[1])[0]
            self.server.Address[info[0]][1] = struct.unpack('=d', info[2])[0] / 100000000
        else:
            self.server.Address[info[0]] = [struct.unpack('=d', info[1])[0], struct.unpack('=d', info[2])[0] / 100000000
                                            ]
        result = [struct.pack('=d', self.server.Address[info[0]][0]), struct.pack('=d',
                                                                                  self.server.Address[info[0]][1])]
        result = batch_handler(result)
        _ = send_handler(MsgType.TYPE_RESPONSE_OK, result)
        # print(self.server.Address)
        self.request.sendall(_)

    def processor_trans_read(self, content):
        result = self.server.transpool.read_serialized()
        if len(result) > 0:
            _ = send_handler(MsgType.TYPE_RESPONSE_OK, batch_handler(result))
        else:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

        self.request.sendall(_)

    def processor_block_write(self, content):
        try:
            block = Block.unpack(content)
        except Exception:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'block unpack error')
        else:
            result = self.server.blockchain.add_block(block)
            self.server.Trans_num += len(block.data.trans)
            for trans in block.data.trans:
                self.server.Trans_size += sys.getsizeof(trans.txid)
            print("chain length1 = ", self.server.blockchain.length + 1)
            print('real length = ', len(self.server.blockchain.chain.queue))
            # print('trans_num = ', self.server.Trans_num)
            # print('trans_size = ', self.server.Trans_size)
            c = 0
            for block in self.server.blockchain.chain.queue:
                c += sys.getsizeof(block.b)
            # print(c)
            # print(self.server.blockchain.size_)
            # print(block.timestamp)
            # print('nnn')

            if result:
                self.server.transpool.remove(block)
                _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')
            else:
                _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

        finally:
            self.request.sendall(_)

    def processor_lightblock_write(self, content):
        try:
            lightblock = LightBlock.unpack(content)
            # print('light = ', lightblock.hash)
        except Exception:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'lightblock unpack error')
        else:
            block = self.processor_block_type_convert(lightblock)
            # print('block = ', block.hash)
            result = self.server.blockchain.add_block(block)
            # print(result)
            # print("chain length = ", self.server.blockchain.length + 1)
            print("chain length = ", len(self.server.blockchain.chain.queue))
            # for i in self.server.blockchain.chain.queue:
            #     print(i.show_block())
            #     print(len(i.data.trans))
            # print(sys.getsizeof(self.server.blockchain.chain.queue))
            # print('nnn')
            # print(self.server.blockchain.size_)
            # print(server.blockchain.utxo_two.utxo)
            # print(server.blockchain.UTXO_num)
            if result:
                a = len(self.server.blockchain.chain.queue)
                # print('all succeed, block.trans =', self.server.blockchain.chain.queue[a - 1].timestamp)
                self.server.transpool.remove(block)
                _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')
            else:
                _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')
        finally:
            self.request.sendall(_)

    def processor_trans_search_txid(self, content):
        try:
            trans = self.server.blockchain.search_transaction(content)
        except TransNotInChain:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')
        else:
            _ = send_handler(MsgType.TYPE_RESPONSE_OK, trans.b)
        finally:
            self.request.sendall(_)

    def processor_prev_hash(self, content):
        self.request.sendall(send_handler(MsgType.TYPE_RESPONSE_OK, self.server.blockchain.chain.queue[-1].hash))

    def processor_block_read(self, content):
        start = bin2int(content[:4])
        end = bin2int(content[4:8])
        # do the search
        result = []
        for i in range(start, end):
            # if start <= server.blockchain.chain.queue[i].index <= end:
            result.append(self.server.blockchain.chain.queue[i].b)
        # send back result
        self.request.sendall(send_handler(MsgType.TYPE_RESPONSE_OK, batch_handler(result)))

    def processor_block_type_convert(self, lightblock: LightBlock) -> Block:
        transaction = []
        # print(lightblock.data.trans_txid)
        trans_in_pool = self.server.transpool.read()
        # print(len(trans_in_pool))
        for t in trans_in_pool:
            # print(t.txid)
            if t.txid in lightblock.data.trans_txid:
                transaction.append(t)

        block = Block(0,  # todo: get index
                      timestamp=lightblock.timestamp,
                      blockdata=BlockData(transaction, lightblock.data.attachment),
                      previous_hash=lightblock.previous_hash,
                      nonce=lightblock.nonce)
        block.hash = lightblock.hash
        return block

    def processor_trans_make(self, content):
        i_ = 0
        add_from = random.randint(0, 5)
        if add_from < 3:
            add_from = 5
        add_to = 0
        add_to_two = random.randint(1, 5)
        _address = [add_from, add_to, add_to_two]
        result = dict()
        # print(_address)
        fd = open('ad1.txt', 'r')
        line = fd.readlines()
        for i in _address:
            line_ = line[i].rstrip()
            pr, pu = line_.split('ENDDING')
            temp = bytes(pu[2:-1], encoding='utf-8')
            temp = temp.replace(b'\r\n', b'\n')
            public_key = temp.replace(b'\\n', b'\n')
            temp = bytes(pr[2:-1], encoding='utf-8')
            temp = temp.replace(b'\r\n', b'\n')
            private_key = temp.replace(b'\\n', b'\n')
            sha = hashlib.sha256()
            sha.update(public_key)
            public_key_hash = sha.digest()
            result[i] = [public_key, private_key, public_key_hash]
        fd.close()

        for utxo in self.server.blockchain.utxo.utxo.items():
            if utxo[1]['to'] == result[_address[0]][2] and utxo[0] not in self.server.Used:
                self.server.Used.append(utxo[0])
                i_ = 1
                # print('11')
                private_key = serialization.load_pem_private_key(result[_address[0]][1], None,
                                                                 backend=default_backend())
                ipt = TransInput([utxo[0]], result[_address[0]][2])
                opt = TransOutput([(utxo[1]['amount']/2, result[_address[1]][2]), (utxo[1]['amount']/2,
                                                                                   result[_address[2]][2])])
                tran = Transaction(ipt, opt)
                tran.ready(private_key)
                content = trans_to_json(tran)
                requests.post('http://127.0.0.1:23390/transaction_post', data=content)
                requests.post('http://127.0.0.1:23391/transaction_post', data=content)
                if result[_address[0]][2] in self.server.Address.keys():
                    self.server.Address[result[_address[0]][2]][0] -= len(tran.b) \
                                                                      * self.server.throughput / (1000 * 2 * 4)
                    self.server.Address[result[_address[0]][2]][1] = time.time()
                else:
                    self.server.Address[result[_address[0]][2]] = [100, time.time()]
                # print('3')
                _ = send_handler(MsgType.TYPE_RESPONSE_OK, tran.b)

                self.request.sendall(_)

                break
        # print('not find')
        if i_ == 0:
            # print('0')
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')
            self.request.sendall(_)
        else:
            pass


class ChainBaseServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """
    Server class to provide chain service
    """
    blockchain = Blockchain()
    transpool = TransPool(blockchain)
    Used = []
    Trans_num = 0
    Trans_size = 0
    Address = dict()
    throughput_list = []
    throughput = 0
    usage = 0
    useful = 0


if __name__ == '__main__':
    address = 'node2'
    print(address)
    with ChainBaseServer(address, ChainMsgHandler) as server:
        server.serve_forever()
