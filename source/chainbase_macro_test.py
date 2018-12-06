# -*- coding: utf-8 -*-
"""
    chainbase
    ~~~~~~~~~

    Implements backend of blockchain

    :author: hank
"""

from source.blockchain import *
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
import ctypes


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
            # MsgType.TYPE_BLOCK_WRITE: self.processor_block_write,

            # convert the lightblock to normal block and write it to the blockchain
            # MsgType.TYPE_LIGHTBLOCK_WRITE: self.processor_lightblock_write,

            # search the transaction that has the given txid
            MsgType.TYPE_TRANS_SEARCH_TXID: self.processor_trans_search_txid,

            # return the previous hash for constructing nonce
            MsgType.TYPE_BLOCK_PREVIOUS_HASH: self.processor_prev_hash,

            # send back blocks whose indexes locate in [start, end]
            MsgType.TYPE_BLOCK_READ: self.processor_block_read,

            # create Trans
            MsgType.TYPE_TRANS_MAKE: self.processor_trans_make,

            # write macro_block_header in blockchain
            MsgType.TYPE_MACRO_BLOCK_HEADER_WRITE: self.processor_macro_block_header_write,

            # append macro_block_body to corresponding macro_block_header
            MsgType.TYPE_MACRO_BLOCK_BODY_WRITE: self.processor_macro_block_body_write,

            # write micro_block and append it to corresponding macro_block_header
            MsgType.TYPE_MICRO_BLOCK_WRITE: self.processor_micro_block_write,

            # get current parent blocks for pending block
            MsgType.TYPE_GET_PARENT_HASH: self.processor_get_parent_hash

        }

        *_, msgtype, content = recv_parser(self.request)

        handlers[msgtype](content)

    def processor_get_parent_hash(self):
        # todo: get state of local DAG and return a binary of referenced hashes
        pass

    def processor_trans_write(self, content):
        result = self.server.transpool.add(content)
        tran = Transaction.unpack(content)
        # print(tran.show_trans())
        # print('ok3')
        if result:
            a = Transaction.unpack(content)
            _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')
            # print('trans_received')
            # print(a.timestamp)
            # print(time.time())
            # print(len(self.server.transpool.trans.queue))
        else:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

        self.request.sendall(_)

    def processor_trans_read(self, content):
        result = self.server.transpool.read_serialized()
        if len(result) > 0:
            _ = send_handler(MsgType.TYPE_RESPONSE_OK, batch_handler(result))
        else:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

        self.request.sendall(_)

    def processor_micro_block_write(self, content):
        try:
            micro_block = MicroBlock.unpack(content)
        except Exception:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'micro_block unpack error')
        else:
            result = self.server.macro_chain.add_micro_block(micro_block)

            if result:
                c = 0
                for i in self.server.macro_chain.micro_block_pool:
                    c += sys.getsizeof(i.b)
                for i_ in self.server.cached_macro_block_body:
                    if micro_block.hash in i_.ref_hash:
                        self.parentless_macro_block_body_process(i_)

                _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')
            else:
                print('failed1', micro_block.hash)
                if self.server.macro_chain.accepted_micro_blocks[micro_block.hash] >= 1:
                    print('pass')
                else:
                    pass
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

    def processor_trans_make(self, content):
        i_ = 0
        add_from = 1
        add_to = random.randint(0, 1)
        add_to_two = 2
        _address = [add_from, add_to,  add_to_two]
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

        for utxo in self.server.macro_chain.utxo.utxo.items():
            if utxo[1]['to'] == result[_address[0]][2] and utxo[0] not in self.server.Used:
                self.server.Used.append(utxo[0])
                # print('1')
                i_ = 1
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
                requests.post('http://127.0.0.1:23392/transaction_post', data=content)

                _ = send_handler(MsgType.TYPE_RESPONSE_OK, tran.b)

                self.request.sendall(_)

                break
        if i_ == 0:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')
            self.request.sendall(_)
        else:
            pass

    def processor_macro_block_header_write(self, content):
        try:
            macro_block_header = MacroBlockHeader.unpack(content)
        except Exception:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'macro_block_header unpack error')
        else:
            result = self.server.macro_chain.add_macro_block_header(macro_block_header)

            if result:
                for i in self.server.cached_macro_block_header:
                    if macro_block_header.hash in i.parent_hash:
                        self.parentless_macro_block_header_process()
                _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')
            else:
                print('failed1', macro_block_header.hash)
                if self.server.macro_chain.accepted_macro_block_headers[macro_block_header.hash] >= 1:
                    print('pass')
                else:
                    self.server.cached_macro_block_header.append(macro_block_header)
                _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

        finally:
            self.request.sendall(_)

    def processor_macro_block_body_write(self, content):
        try:
            macro_block_body = MacroBlockBody.unpack(content)
        except Exception:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'macro_block_body unpack error')
        else:
            result = self.server.macro_chain.add_macro_block_body(macro_block_body)

            if result:
                if macro_block_body in self.server.cached_macro_block_body:
                    self.server.cached_macro_block_body.remove(macro_block_body)
                _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')
            else:
                print('failed1', macro_block_body.hash)
                if self.server.macro_chain.accepted_macro_block_bodies[macro_block_body.hash] >= 1:
                    print('pass')
                else:
                    self.server.cached_macro_block_body.append(macro_block_body)
                _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

        finally:
            self.request.sendall(_)

    def parentless_macro_block_header_process(self):
        print('parentless')
        flag = 1
        if len(self.server.cached_macro_block_header) != 0:
            while flag > 0:
                for i in self.server.cached_macro_block_header:
                    if i.hash in self.server.macro_chain.accepted_macro_block_headers.keys():
                        del self.server.macro_chain.accepted_macro_block_headers[i.hash]
                    result = self.server.macro_chain.add_macro_block_header(i)
                    if result:
                        self.server.cached_macro_block_header.remove(i)
                        if len(self.server.cached_macro_block_header) == 0:
                            flag = 0
                        else:
                            flag = 1
                        break
                    flag = 0

    def parentless_macro_block_body_process(self, macro_block_body: MacroBlockBody):
        del self.server.macro_chain.accepted_macro_block_bodies[macro_block_body.hash]
        self.processor_macro_block_body_write(macro_block_body)


class ChainBaseServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """
    Server class to provide chain service
    """
    macro_chain = MacroChain()
    Used = list()
    cached_macro_block_header = list()
    cached_macro_block_body = list()
    blockchain = Blockchain()
    transpool = TransPool(blockchain)


if __name__ == '__main__':
    address = 'node2'
    print(address)
    with ChainBaseServer(address, ChainMsgHandler) as server:
        server.serve_forever()

