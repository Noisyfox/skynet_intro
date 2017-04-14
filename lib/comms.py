import struct
import binascii

from Crypto.Cipher import XOR
from Crypto.Hash import HMAC, SHA256

from dh import create_dh_key, calculate_dh_secret


class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.hmac = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()

        self.tag_size = 16

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret 

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key, key_len=64)
            print("Shared session key: {}".format(binascii.hexlify(shared_hash)))

            # The first 256 bit from shared hash is the key of hmac
            self.hmac = HMAC.new(shared_hash[:32], digestmod=SHA256)

            # TODO: exchange iv
            # TODO: use a global bloom filter to avoid iv re-use in a reasonable time period,
            # and we can add a time stamp after iv to avoid replay if the iv filter is reset

            # The last 256 bit from shared hash is the key of hmac
            cipher_key = shared_hash[:-32]
            # TODO: init cipher with aes-cfb using cipher_key and iv
            # Default XOR algorithm can only take a key of length 32
            self.cipher = XOR.new(shared_hash[:4])

    def send(self, data):
        if self.cipher:
            pre_auth_text = self.cipher.encrypt(data)
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(pre_auth_text)))
        else:
            pre_auth_text = data

        if self.hmac:
            # generate tag
            hmac_s = self.hmac.copy()
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

        if self.hmac:
            # check tag
            if pkt_len < self.tag_size:
                self.auth_error()

            tag = authed_data[-self.tag_size:]
            if self.verbose:
                print("Received data tag {}".format(repr(tag)))

            cipher_text = authed_data[:pkt_len - self.tag_size]
            hmac_s = self.hmac.copy()
            hmac_s.update(cipher_text)
            tag_calc = hmac_s.digest()[:self.tag_size]
            if self.verbose:
                print("Calculated data tag {}".format(repr(tag_calc)))

            if tag != tag_calc:
                self.auth_error()
        else:
            cipher_text = authed_data

        if self.cipher:
            # decrypt data
            data = self.cipher.decrypt(cipher_text)
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
