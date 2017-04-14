from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol import KDF
from Crypto.Random import random

from dh.groups import get_group

# use default group 17 with 6144 bit prime
prime, generator = get_group()
# for AES with 256 key len, we need exponent with len around 540
exponent_len = 540


def create_dh_key():
    # Creates a Diffie-Hellman key
    # Returns (public, private)
    private_key = random.getrandbits(exponent_len)
    public_key = pow(generator, private_key, prime)

    return public_key, private_key


def _check_public_key(public_key):
    """
    Check the other party's public key to make sure it's valid.
    Since a safe prime is used, verify that the Legendre symbol == 1
    """
    if 2 < public_key < prime - 1:
        if pow(public_key, (prime - 1) // 2, prime) == 1:
            return True
    return False


# derivate key from dh secret
def calculate_dh_secret(their_public, my_private, key_len=32):
    # Check if other party's public key is valid
    if not _check_public_key(their_public):
        raise Exception("Invalid public key! Danger!")

    # Calculate the shared secret
    shared_secret = pow(their_public, my_private, prime)

    # Hash the value so that:
    # (a) There's no bias in the bits of the output
    #     (there may be bias if the shared secret is used raw)
    # (b) We can convert to raw bytes easily
    # (c) We could add additional information if we wanted
    # Feel free to change SHA256 to a different value if more appropriate

    # shared_hash = SHA256.new(bytes(str(shared_secret), "ascii")).hexdigest()
    shared_hash = KDF.PBKDF2(shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='little'),
                             b"team.football", key_len, prf=lambda p, s: HMAC.new(p, s, SHA256).digest())

    return shared_hash
