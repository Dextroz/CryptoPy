from setuptools import setup, find_packages

with open("README.md", "r") as readme:
    long_description = readme.read()

setup(
    name="CryptoPy",
    version="0.0.2",
    author="Dextroz",
    description="A Python module to easily encrypt and decrypt files.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Dextroz/CryptoPy",
    packages=find_packages(),
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
    ],
    keywords="Python 3 Encrypt Decrypt Encryption Decryption AES file files CryptoPy",
)