try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from os.path import abspath
    from os import remove, rename
except ImportError as err:
    print(f"Failed to import required modules: {err}")


class CryptoPy:
    """
    The base class for CryptoPy.
    """

    def __init__(self, KEY=None):
        """
        Class initialisation.
            :param KEY: A byte string. Example: b'\xcd\xa0\x0f\x97%.\xbb\xf7\xe0\xd3\xa9\x86i\xec\xa0:'.
        """
        VERSION = "0.0.1"

        if KEY is None:
            self.KEY = get_random_bytes(16)
            self.RANDOM_KEY = True
        else:
            self.KEY = KEY

    def encrypt_plaintext(self, plaintext, key):
        """
        Encrypt plaintext contents using a key.
            :param plaintext: The plaintext to be encrypted.
            :param key: The secret key to use in the symmetric cipher.
            :rtype ciphertext, tag: an AES object, of the applicable mode.
        """
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return cipher, ciphertext, tag

    def encrypt_file(self, file_path):
        """
        Encrypt the contents of a file.
            :param file_path: The PATH of the file to be encrypted.
            :rtype string: The string PATH to the file containing the secret key; if no KEY is supplied.
        """
        # Check to ensure the file isn't already encrypted.
        if file_path.endswith(".enc"):
            raise TypeError(
                "Error: You cannot encrypt a file which is already encrypted."
            )
        else:
            try:
                with open(abspath(file_path), "rb") as data:
                    try:
                        with open(f"{file_path}.enc", "wb") as encrypt_file:
                            cipher, ciphertext, tag = self.encrypt_plaintext(
                                data.read(), self.KEY
                            )
                            [
                                encrypt_file.write(_)
                                for _ in (cipher.nonce, tag, ciphertext)
                            ]
                    except IOError as err:
                        raise IOError(
                            f"Error: Failed to create new encrypted file: {err}"
                        )
            except IOError as err:
                raise IOError(f"Error: Failed to open {file_path}: {err}")
            if self.RANDOM_KEY:
                # Write key to file.
                try:
                    with open(f"{file_path}.key", "wb") as key_file:
                        key_file.write(self.KEY)
                except IOError as err:
                    raise IOError(f"Error: Failed to create key file: {err}")
                # Remove unencrypted version of the file.
                remove(abspath(file_path))
                # Return the PATH to the key file.
                return abspath(f"{file_path}.key")

    def decrypt_ciphertext(self, ciphertext, key, nonce, tag):
        """
        Decrypt a files ciphertext content using a key.
            :param ciphertext: The ciphertext to be decrypted.
            :param key: The secret key to use in the symmetric cipher to decrypt ciphertext.
            :param nonce: The nonce created during the encryption process.
            :param tag: The tag created during the encryption process.
            :rtype plaintext: The decrypted plaintext.
        """
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext

    def decrypt_file(self, file_path):
        """
        Encrypt the contents of a file.
            :param file_path: The PATH of the file to be encrypted.
            :rtype string: The string PATH to the decrypted file.
        """
        if file_path.endswith(".enc"):
            try:
                with open(abspath(file_path), "r+b") as encrypted_file:
                    nonce, tag, ciphertext = [
                        encrypted_file.read(_) for _ in (16, 16, -1)
                    ]
                    plaintext = self.decrypt_ciphertext(
                        ciphertext, self.KEY, nonce, tag
                    )
                    encrypted_file.seek(0)
                    encrypted_file.write(plaintext)
                    encrypted_file.truncate()
            except IOError as err:
                raise IOError(f"Error: Failed to open encrypted file: {err}")
            # Rename file as no longer encrypted.
            new_file_name = file_path.replace(".enc", "")
            rename(abspath(file_path), new_file_name)
            # Return the PATH to the decrypted file.
            return abspath(new_file_name)
        else:
            raise TypeError(
                "Error: The file must encrypted before it can be decrypted."
            )

