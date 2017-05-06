import os

import math

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from lib.files import FileCipher


def decrypt_valuables(f):
    # Load the private key
    with open('master_key.pem', 'rb') as kf:
        key = RSA.importKey(kf.read())

    # get encrypted secret size using key size
    secret_size = int(math.ceil(key.size() / 256) * 256 / 8)

    if len(f) < secret_size:
        raise Exception("Illegal file size!")

    enc_secret = f[:secret_size]
    data = f[secret_size:]

    # Decrypt secret with private key
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    secret = cipher.decrypt(enc_secret)

    # Decrypt data using secret
    plain_text = FileCipher(secret).decrypt(data)
    decoded_text = str(plain_text, 'ascii')
    print(decoded_text)

if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
