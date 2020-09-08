# aes-crypter

This is a wrapper for PyCrypto's AES function.
It uses AES in it's EAX mode.

To use it, simply type:
```python3
encrypted = encrypt(password, message)
```
Replace `password` with your password, it will be automatically hashed.
Replace `message` with your data and you're good to go!

You will get a **Dictionary** as output, it is structured like this:
```python3
{
	'ciphertext' : b'your encrypted data'
	'nonce' : b'the nonce of the aes algorythm'
	'tag' : b'the tag of the aes algorythm'
}
```

To decrypt your data, just use the `decrypt()` function like this:
```python3
plaintext = decrypt(encrypted_data_dictionary, password)
```

Pass the Dictionary and the password from above in and you should get your message!
