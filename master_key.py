# for generating new key pairs
import os
from Crypto.PublicKey import RSA

if __name__ == '__main__':
    i = input("This will overwrite any existing keys! Proceed? (y/N):")
    if i.lower() == 'y':
        print('Generating RSA key...')
        key = RSA.generate(bits=2048)

        print('Saving private key...')
        with open('master_key.pem', 'wb') as f:
            f.write(key.exportKey('PEM'))

        print('Saving public key...')
        with open(os.path.join('lib', 'key_rsa.pub.pem'), 'wb') as f:
            f.write(key.publickey().exportKey('PEM'))

        print('All done!')
