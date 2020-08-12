try:
    from Crypto.Cipher import AES
    import hashlib
except ImportError:
    print('Please install PyCryptodome')

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
        citext, tag = ci.encrypt_and_digest(message.encode())
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
            ci.decrypt(enc_dict['ciphertext']
            try:
                ci.verify(enc_data['tag']
            except ValueError:
                raise Unverified('Key incorrect or message corrupted.')

        except NameError:
            raise NotProperlyDefined('Please use a dictionary with the keys \"key, tag, nonce, ciphertext\"'
            
    else:
        raise(ValueError('Please use a dictionary as argument'))
