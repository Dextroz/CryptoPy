# CryptoPy 🔐
A Python module to easily encrypt and decrypt files.

CryptoPy is written in Python 3.7 🐍

## Example Usage

CryptoPy currently uses the Advanced Encryption Standard (AES) to encrypt files.

By default, if the user doesn't supply a `KEY` to `CryptoPy`, a random key is generated and used for encryption.
However, if a `KEY` is supplied, the assumption is made that this `KEY` is stored or known to the user by some other means.

The `KEY` must be a byte string. An example is: `b'\xcd\xa0\x0f\x97%.\xbb\xf7\xe0\xd3\xa9\x86i\xec\xa0:'`.

Below shows an example of CryptoPy in action on a file within this project.

```python
# Encrypt File.
# encrypt_file ONLY returns a string PATH to the key file if a key isn't supplied during initialisation.
key_file_path = CryptoPy().encrypt_file("../Pipfile.lock")
print(key_file_path)
# Open the file containing the key generated by CryptoPy during encryption process.
# Remember, this file is only produced if no `KEY` was supplied during initialisation of CryptoPy.
with open("../Pipfile.lock.key", "rb") as key_file:
    key = key_file.read()
# Use the key to decrypt the previously encrypted file.
# decrypt_file returns a string PATH to the decrypted file.
decrypted_file_path = CryptoPy(key).decrypt_file("../Pipfile.lock.enc")
print(decrypted_file_path)
```

To use CryptoPy in your own project import using `from CryptoPy import CryptoPy`.

## Dependencies / Installation.

```
[dev-packages]
black = "*"

[packages]
pycryptodome = "*"
```

Install dependencies using either:
* `pipenv install`, `pip3 install -r requirements.txt`, `python setup.py install`, `pip3 install CryptoPy`.

## Disclaimer

* I am by no means a crypto expert, if you spot an issue with the module, go ahead and fork the repo, submit an issue or PR. 🙂

* I am **NOT** responsible for any loss or corruption of file data/encryption keys. By using this module, you accept the risk that issues or errors **could** occur resulting in loss of data/keys.

## Changelog

* 0.0.2 - Added PyPi support. Altered `encrypt_file` to overwrite the file supplied for encryption instead of creating a new file and deleting the old one (done in version 0.0.1).

* 0.0.1 - Inital relase. Can encrypt or decrypt a user specified file using the Advanced Encryption Standard (AES).

## Authors -- Contributors

* **Dextroz** - *Author* - [Dextroz](https://github.com/Dextroz)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) for details.
