
from Crypto.Cipher import AES
import hashlib


class Unverified(Exception):
    pass


class NotProperlyDefined(Exception):
    pass

def encrypt(password, message):
    """Encrypt a message using AES, returns a dictionary"""
    try:
        sha = hashlib.sha256(password.encode())
        key = sha.digest()
        messec = message.encode()
        out = dict()
        ci = AES.new(key, AES.MODE_EAX)
        nonce = ci.nonce
        citext, tag = ci.encrypt_and_digest(messec)
        out['key'] = key
        out['ciphertext'] = citext
        out['tag'] = tag
        out['nonce'] = nonce
        return out

    except AttributeError:
        raise ValueError('Arguments of encrypt() must be strings')


def decrypt(enc_dict):
    if isinstance(enc_dict, dict):
        try:
            ci = AES.new(enc_dict['key'], AES.MODE_EAX, nonce=enc_dict['nonce'])
            plain = ci.decrypt(enc_dict['ciphertext'])
            ci.verify(enc_dict['tag'])
            return plain
        except ValueError:
            raise Unverified('Key incorrect or message corrupted.')
            
    else:
        raise(ValueError('Please use a dictionary as argument'))


print('Encrypted Data:')
enc = encrypt('1234', 'Uhu')
print(enc)
print('')

print('Decrypted Data:\n')
plain = decrypt(enc)
