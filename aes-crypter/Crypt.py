from Crypto.Cipher import AES
import hashlib

def encrypt(password, message):
    """Encrypt a message using AES, returns a dictionary"""

    # Create a new SHA256 object initialized with the given password
    sha = hashlib.sha256(password.encode())
    # Saves the digest of the password as the key
    key = sha.digest()
    # Encodes the given message
    messec = message.encode()
    # Creates output dictionary
    out = dict()
    # Creates an AES object and saves it's nonce
    ci = AES.new(key, AES.MODE_EAX)
    nonce = ci.nonce
    # Encrypts the message
    citext, tag = ci.encrypt_and_digest(messec)
    # Saves everything in the output dict and returns it.
    out['ciphertext'] = citext
    out['tag'] = tag
    out['nonce'] = nonce
    return out


def decrypt(enc_dict, password):
    """Decrypts a message using AES, needs an dictionary containing ciphertext, nonce and tag, also uses a password."""
    # Creates Hash of the password
    sha = hashlib.sha256(password.encode())
    # Creates AES object
    ci = AES.new(key=sha.digest(), mode=AES.MODE_EAX, nonce=enc_dict['nonce'])
    # Decrypts, verifies and returns the ciphertext.
    plain = ci.decrypt(enc_dict['ciphertext'])
    ci.verify(enc_dict['tag'])
    return plain
