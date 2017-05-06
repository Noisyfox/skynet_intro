import os

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol import KDF
from Crypto.PublicKey import RSA

# Instead of storing files on disk,
# we'll save them in memory for simplicity
from Crypto.Random import random

filestore = {}
# Valuable data to be sent to the botmaster
valuables = []

###


class FileCipher(object):
    # not longer than the RSA modulus (in bytes) minus 2, minus twice the hash output size.
    # RSA modulus lens = 2048 bits (256 bytes)
    # Hash func = SHA256 (32 bytes)
    secret_size = 256 - 2 - 2 * 32  # 190 bytes

    key_hmac_size = 32  # bytes
    key_cipher_size = 32  # for AES256
    iv_size = 16  # for AES CBC mode which iv size = block size = 16 bytes
    key_block_size = key_hmac_size + key_cipher_size + iv_size

    tag_size = 32
    block_size = 16

    def __init__(self, secret: bytes):
        if len(secret) < FileCipher.secret_size:
            raise Exception('Not enough bytes for key block!')

        key_block_bytes = KDF.PBKDF2(secret, b"team.football.file",
                                     FileCipher.key_block_size, prf=lambda p, s: HMAC.new(p, s, SHA256).digest())

        def split(_len, a):
            return a[:_len], a[_len:]

        b = key_block_bytes

        MAC_secret, b = split(FileCipher.key_hmac_size, b)
        aes_key, b = split(FileCipher.key_cipher_size, b)
        aes_IV, b = split(FileCipher.iv_size, b)

        self.hmac = HMAC.new(MAC_secret, digestmod=SHA256)
        self.cipher = AES.new(aes_key, AES.MODE_CBC, aes_IV)

    def _tag(self, data: bytes)->bytes:
        self.hmac.update(data)
        return self.hmac.digest()[:self.tag_size]

    def encrypt(self, f: bytes)->bytes:
        data = self.pad(f)
        data = self.cipher.encrypt(data)
        tag = self._tag(data)

        return data + tag

    def decrypt(self, f: bytes)->bytes:
        f_len = len(f)
        if f_len < self.tag_size:
            self.auth_error()

        tag = f[-self.tag_size:]
        cipher_text = f[:f_len - self.tag_size]
        tag_calc = self._tag(cipher_text)

        if tag != tag_calc:
            self.auth_error()

        return self.cipher.decrypt(cipher_text)

    # Padding function, implementing PKCS#7
    def pad(self, s):
        s_bytearray = bytearray(s)
        for i in range(1, self.block_size - len(s) % self.block_size + 1):
            s_bytearray.append(self.block_size - len(s) % self.block_size)

        s = bytes(s_bytearray)
        return s

    # Unpadding function
    def unpad(self, s):
        return s[:-int(s[len(s) - 1])]

    def auth_error(self):
        raise Exception("Auth check failed!")


def save_valuable(data):
    valuables.append(data)

def encrypt_for_master(data):
    # Encrypt the file so it can only be read by the bot master
    # Load the public key
    with open(os.path.join(os.path.dirname(__file__), 'key_rsa.pub.pem'), 'rb') as kf:
        key = RSA.importKey(kf.read())

    # Generate random secret for AES
    secret = random.getrandbits(FileCipher.secret_size * 8).to_bytes(FileCipher.secret_size, byteorder='little')

    # Encrypt with AES using secret
    cipher_data = FileCipher(secret).encrypt(data)

    # Encrypt secret with PKCS1_OAEP
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    enc_secret = cipher.encrypt(secret)

    # The result is RSA(secret) + AES_CBC_THEN_HMAC(secret, data)
    return enc_secret + cipher_data

def upload_valuables_to_pastebot(fn):
    # Encrypt the valuables so only the bot master can read them
    valuable_data = "\n".join(valuables)
    valuable_data = bytes(valuable_data, "ascii")
    encrypted_master = encrypt_for_master(valuable_data)

    # "Upload" it to pastebot (i.e. save in pastebot folder)
    f = open(os.path.join("pastebot.net", fn), "wb")
    f.write(encrypted_master)
    f.close()

    print("Saved valuables to pastebot.net/%s for the botnet master" % fn)

###

def verify_file(f):
    # Verify the file was sent by the bot master
    # TODO: For Part 2, you'll use public key crypto here
    # Naive verification by ensuring the first line has the "passkey"
    lines = f.split(bytes("\n", "ascii"), 1)
    first_line = lines[0]
    if first_line == bytes("Caesar", "ascii"):
        return True
    return False

def process_file(fn, f):
    if verify_file(f):
        # If it was, store it unmodified
        # (so it can be sent to other bots)
        # Decrypt and run the file
        filestore[fn] = f
        print("Stored the received file as %s" % fn)
    else:
        print("The file has not been signed by the botnet master")

def download_from_pastebot(fn):
    # "Download" the file from pastebot.net
    # (i.e. pretend we are and grab it from disk)
    # Open the file as bytes and load into memory
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        return
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    process_file(fn, f)

def p2p_download_file(sconn):
    # Download the file from the other bot
    fn = str(sconn.recv(), "ascii")
    f = sconn.recv()
    print("Receiving %s via P2P" % fn)
    process_file(fn, f)

###

def p2p_upload_file(sconn, fn):
    # Grab the file and upload it to the other bot
    # You don't need to encrypt it only files signed
    # by the botnet master should be accepted
    # (and your bot shouldn't be able to sign like that!)
    if fn not in filestore:
        print("That file doesn't exist in the botnet's filestore")
        return
    print("Sending %s via P2P" % fn)
    sconn.send(fn)
    sconn.send(filestore[fn])

def run_file(f):
    # If the file can be run,
    # run the commands
    pass
