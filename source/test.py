# -*- coding: utf-8 -*-
"""
    conchain
    ~~~~~~~~~~
    Implements blockchain consensus mechanisms
    :author: hank
"""
from source.transfer import MsgType, PeerManager, recv_parser, send_handler, batch_handler, batch_parser
from source.blockchain import Transaction, Block, Attachment, BlockData

from random import randrange, seed
import struct
import hashlib
from queue import Queue
import socketserver
import socket
import concurrent.futures
from multiprocessing import Value, Pool, Lock
from functools import partial
from typing import List
import time

MINE_TOP = 2 ** 31
MINE_SWITCH = Value('i', 1)


def mine(prev_hash, target):
    return PoWServer.mine(prev_hash, target)


class PoWServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

    def __init__(self, server_name: str, server_address, handler, chainbase_address):
        self.name = server_name
        self.prev_hash = b''
        self.target = (2 ** 234 - 1).to_bytes(32, byteorder='big')
        self.chainbase_address = chainbase_address
        self.peer = PeerManager()
        self.workers = Pool()
        self.start = 0
        self.end = 0
        self.usage = 0
        self.usage_two = 0

        super().__init__(server_address, handler, bind_and_activate=True)

    def serve_forever(self, poll_interval=0.5):

        self.init_prev_hash()
        self.init_target()
        self.start_miner()

        super().serve_forever()

    def start_miner(self):
        self.__set_mine(True)
        self.start = time.time()
        ore = self.workers.apply_async(mine,
                                       args=(self.prev_hash, self.target),
                                       callback=partial(self.on_new_block_mined, self))

    @staticmethod
    def stop_miner():
        PoWServer.__set_mine(False)

    @staticmethod
    def on_new_block_mined(self: 'PoWServer', result):
        """
        try to add the block that the server itself mines to the chainbase
        :param self: the instance of PoWServer
        :param future: Future object contains mining result
        :return: None
        """
        prev_hash_, target_, nonce = result
        print('return')
        print(nonce)
        if prev_hash_ == self.prev_hash and target_ == self.target:

            if nonce < 0:  # mining is stopped by stop_miner
                self.end = time.time()
                self.usage_two += self.end - self.start
                print('usage_two', self.usage)
                return
            self.end = time.time()
            self.usage += self.end - self.start
            self.usage_two += self.end - self.start
            print('usage', self.usage)
            print('usage_two', self.usage_two)
            block = self.make_block(nonce)  # mining stops because a nonce have been found

            print('block mined:')
            print(block.show_block())

            self.peer.sendall_block(msgtype=MsgType.TYPE_NEW_BLOCK, content=block.b)
            assert self.add_block(block) is True
            self.prev_hash = block.hash
            self.start_miner()  # start a new miner
        else:
            print('ok')

    def on_new_block_received(self, block):
        print('block receiced')
        block = Block.unpack(block)
        if self.add_block(block):
            print('try to stop current miner')
            self.stop_miner()  # stop current miner
            self.prev_hash = block.hash
            self.peer.sendall_block(msgtype=MsgType.TYPE_NEW_BLOCK, content=block.b)
            print('try to start a new miner')
            self.start_miner()  # start a new miner

    def init_prev_hash(self):
        """get previous hash from chainbase when initializing"""
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.chainbase_address)
            s.sendall(send_handler(MsgType.TYPE_BLOCK_PREVIOUS_HASH, b''))
            *_, msgtype, content = recv_parser(s)

            self.prev_hash = content
            print('prev_hash = ', content)

    def init_target(self):
        pass

    def make_block(self, nonce) -> Block:
        trans = self.__get_trans()

        info = Attachment()
        info.add_data(b'mined by ' + self.name.encode())
        info.ready()

        block = Block(0,  # todo: get index
                      timestamp=time.time(),
                      blockdata=BlockData(trans, info),
                      previous_hash=self.prev_hash,
                      nonce=nonce)
        return block

    def add_block(self, block: Block) -> bool:
        """
        add the block to the chainbase
        :param block: binary block
        :return: True | False
        """
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.chainbase_address)
            s.sendall(send_handler(MsgType.TYPE_BLOCK_WRITE, block.b))
            *_, msgtype, content = recv_parser(s)

            print('result of adding block', content)
        return msgtype == MsgType.TYPE_RESPONSE_OK

    def acquire_block(self):
        pass

    @staticmethod
    def __keep_mining() -> bool:
        if MINE_SWITCH.value == 1:
            return True
        else:
            return False

    @staticmethod
    def __set_mine(state: bool):
        if state:
            MINE_SWITCH.value = 1
        else:
            MINE_SWITCH.value = 0

    def __get_trans(self) -> List[Transaction]:
        # self.chainbase_address
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.chainbase_address)
            s.sendall(send_handler(MsgType.TYPE_TRANS_READ, b''))
            *_, msgtype, content = recv_parser(s)

            trans = []  # todo: the first transaction should reward the miner,
            # todo: the server may have a property named owner_address
            if msgtype == MsgType.TYPE_RESPONSE_OK:
                trans += batch_parser(content)

            return [Transaction.unpack(t) for t in trans]

    @staticmethod
    def mine(prev_hash, target):
        """
        find a valid nonce
        :param prev_hash:
        :param target:
        :return: Tuple of (prev_hash, target, nonce)
        """
        seed()
        initial = randrange(0, MINE_TOP)  # [0, 2**32]

        print('mining')

        for nonce in range(initial, MINE_TOP):
            if not PoWServer.__keep_mining():
                print('stop mining')
                return prev_hash, target, -1
            hash_ = PoWServer.__calc_hash(prev_hash, nonce)

            if hash_ < target:
                return prev_hash, target, nonce

        for nonce in range(0, initial):
            if not PoWServer.__keep_mining():
                print('stop mining')
                return prev_hash, target, -1
            hash_ = PoWServer.__calc_hash(prev_hash, nonce)

            if hash_ < target:
                return prev_hash, target, nonce

    @staticmethod
    def __calc_hash(prev_hash, nonce: int) -> bytes:  # calculate SHA256(SHA256(prev_hash+nonce))
        sha = hashlib.sha256()
        sha.update(prev_hash)
        sha.update(struct.pack('=I', nonce))
        hash_ = sha.digest()
        sha = hashlib.sha256()
        sha.update(hash_)
        hash_ = sha.digest()

        return hash_


class PowHandler(socketserver.StreamRequestHandler):
    def handle(self):
        handlers = {
            MsgType.TYPE_NEW_BLOCK: self.server.on_new_block_received,

            MsgType.TYPE_BLOCK_READ: self.server.acquire_block,

            MsgType.TYPE_NODE_DISCOVER: self.server.peer.peer_discover
        }

        *_, msgtype, content = recv_parser(self.request)

        handlers[msgtype](content)


if __name__ == '__main__':
    import sys

    address = ('localhost', 8000)
    chainbase_address = 'node1'

    with PoWServer('node1', address, PowHandler, chainbase_address) as server:
        server.peer.peer_discover(('localhost', 8001))
        server.serve_forever()
