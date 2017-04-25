import struct
import binascii

from Crypto.Cipher import XOR
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol import KDF
from Crypto.Random import random

from dh import create_dh_key, calculate_dh_secret


# Split the derived key derived by PBKDF2
class KeyBlock(object):
    key_hmac_size = 32  # bytes
    key_cipher_size = 32  # for AES256
    iv_size = 16  # for AES CBC or CFB mode which iv size = block size = 16 bytes
    key_block_size = key_hmac_size * 2 + key_cipher_size * 2 + iv_size * 2

    def __init__(self, key_block_bytes):
        if len(key_block_bytes) < KeyBlock.key_block_size:
            raise Exception('Not enough bytes for key block!')

        def split(_len, a):
            return a[:_len], a[_len:]

        b = key_block_bytes

        self.client_write_MAC_secret, b = split(KeyBlock.key_hmac_size, b)
        self.server_write_MAC_secret, b = split(KeyBlock.key_hmac_size, b)
        self.client_write_key, b = split(KeyBlock.key_cipher_size, b)
        self.server_write_key, b = split(KeyBlock.key_cipher_size, b)
        self.client_write_IV, b = split(KeyBlock.iv_size, b)
        self.server_write_IV, b = split(KeyBlock.iv_size, b)

    def __str__(self) -> str:
        return 'client_write_MAC_secret:%s\n' \
               'server_write_MAC_secret:%s\n' \
               'client_write_key:%s\n' \
               'server_write_key:%s\n' \
               'client_write_IV:%s\n' \
               'server_write_IV:%s' % (
                   binascii.hexlify(self.client_write_MAC_secret),
                   binascii.hexlify(self.server_write_MAC_secret),
                   binascii.hexlify(self.client_write_key),
                   binascii.hexlify(self.server_write_key),
                   binascii.hexlify(self.client_write_IV),
                   binascii.hexlify(self.server_write_IV),)


class StealthConn(object):
    random_size = 32  # bytes
    tag_size = 16

    def __init__(self, conn, client=False, server=False, verbose=False):
        if client == server:
            raise Exception("Exo me? You can't be either nor neither of client / server.")

        self.conn = conn
        self.hmac_send = None
        self.hmac_recv = None
        self.cipher_send = None
        self.cipher_recv = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        # get server and client random
        self_random = random.getrandbits(StealthConn.random_size * 8).to_bytes(StealthConn.random_size,
                                                                               byteorder='little')
        self.send(self_random)
        other_random = self.recv()
        if len(other_random) != self.random_size:
            raise Exception('Random size error!')

        if self.client:
            server_random = other_random
            client_random = self_random
        else:
            server_random = self_random
            client_random = other_random

        # Exchange master_secret via Diffie-Hellman key exchange
        my_public_key, my_private_key = create_dh_key()
        # Send them our public key
        self.send(bytes(str(my_public_key), "ascii"))
        # Receive their public key
        their_public_key = int(self.recv())
        # Obtain our shared secret
        master_secret = calculate_dh_secret(their_public_key, my_private_key)
        print("Shared master secret: {}".format(binascii.hexlify(master_secret)))

        # Derive hmac key, encrypt key and iv from server_random, client_random and master_secret using PBKDF2
        # Refer to RFC2898
        key_block_bytes = KDF.PBKDF2(master_secret + server_random + client_random, b"team.football",
                                     KeyBlock.key_block_size, prf=lambda p, s: HMAC.new(p, s, SHA256).digest())

        print("key_block_bytes: {}".format(binascii.hexlify(key_block_bytes)))

        key_block = KeyBlock(key_block_bytes)

        print("key_block:\n{}".format(key_block))

        if self.client:
            self.hmac_recv = HMAC.new(key_block.server_write_MAC_secret, digestmod=SHA256)
            self.hmac_send = HMAC.new(key_block.client_write_MAC_secret, digestmod=SHA256)
            # TODO: init cipher with aes-cfb using cipher_key and iv
            self.cipher_recv = XOR.new(key_block.server_write_key[:4])
            self.cipher_send = XOR.new(key_block.client_write_key[:4])
        else:
            self.hmac_recv = HMAC.new(key_block.client_write_MAC_secret, digestmod=SHA256)
            self.hmac_send = HMAC.new(key_block.server_write_MAC_secret, digestmod=SHA256)
            # TODO: init cipher with aes-cfb using cipher_key and iv
            self.cipher_recv = XOR.new(key_block.client_write_key[:4])
            self.cipher_send = XOR.new(key_block.server_write_key[:4])

    def send(self, data):
        if self.cipher_send:
            pre_auth_text = self.cipher_send.encrypt(data)
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(pre_auth_text)))
        else:
            pre_auth_text = data

        if self.hmac_send:
            # generate tag
            hmac_s = self.hmac_send.copy()
            hmac_s.update(pre_auth_text)
            tag = hmac_s.digest()[:self.tag_size]
            if self.verbose:
                print("Data tag: {}".format(repr(tag)))

            # append tag at the tail of the cipher text
            authed_text = pre_auth_text + tag
        else:
            authed_text = pre_auth_text

        if self.verbose:
            print("Sending packet of length {}".format(len(authed_text)))

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(authed_text))
        self.conn.sendall(pkt_len)
        self.conn.sendall(authed_text)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        received_size = 0
        authed_data = b''
        while received_size < pkt_len:
            r = self.conn.recv(pkt_len - received_size)
            received_size += len(r)
            authed_data += r

        if self.verbose:
            print("Receiving packet of length {}".format(pkt_len))

        if self.hmac_recv:
            # check tag
            if pkt_len < self.tag_size:
                self.auth_error()

            tag = authed_data[-self.tag_size:]
            if self.verbose:
                print("Received data tag {}".format(repr(tag)))

            cipher_text = authed_data[:pkt_len - self.tag_size]
            hmac_s = self.hmac_recv.copy()
            hmac_s.update(cipher_text)
            tag_calc = hmac_s.digest()[:self.tag_size]
            if self.verbose:
                print("Calculated data tag {}".format(repr(tag_calc)))

            if tag != tag_calc:
                self.auth_error()
        else:
            cipher_text = authed_data

        if self.cipher_recv:
            # decrypt data
            data = self.cipher_recv.decrypt(cipher_text)
            if self.verbose:
                print("Encrypted data: {}".format(repr(cipher_text)))
                print("Original data: {}".format(data))
        else:
            data = cipher_text

        return data

    def auth_error(self):
        raise Exception("Auth check failed!")

    def close(self):
        self.conn.close()
