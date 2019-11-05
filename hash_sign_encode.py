import sys
import argparse
import hashlib
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding


def bytes_to_text(text_bytes):
    text = ''
    for b in text_bytes:
        if len(text) > 0:
            text = text + ','
        text = text + str(b)
    return text


def hash_to_text(hash_object):
    return bytes_to_text(bytes.fromhex(hash_object.hexdigest()))


def encode_text(text):
    return text.encode('utf-8')


def hash_text(text):
    return hashlib.sha256(text)


def sign_hash(hashed_bytes, key_file_name):
    chosen_hash = hashes.SHA256()

    with open(key_file_name, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

        signature = private_key.sign(
            hashed_bytes,
            padding.PKCS1v15(),
            utils.Prehashed(chosen_hash)
        )

        return signature


def encode_bytes(signed_hash):
    return base64.encodebytes(signed_hash)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Hash, Sign and Encode text for FI.API')
    parser.add_argument('text', action='store')
    parser.add_argument('-k', '--keyfile', action='store', required=True)

    try:
        arguments = parser.parse_args()

        print("RunHash")
        print('Using:', arguments.text)

        encoded_bytes = encode_text(arguments.text)
        print('UTF8EncodedData:',  bytes_to_text(encoded_bytes))

        hashed_text = hash_text(encoded_bytes)
        print('HashedData (SHA256):', hash_to_text(hashed_text))

        print()
        print("RunSign")
        print("Using:", hash_to_text(hashed_text))
        signed_bytes = sign_hash(hashed_text.digest(), arguments.keyfile)
        print('SignedData:', bytes_to_text(signed_bytes))

        print()
        print("RunEncode")
        print("Using:", bytes_to_text(signed_bytes))
        encoded_text = encode_bytes(signed_bytes)
        print('EncodedData:', encoded_text.decode('utf-8').replace("\n", ""))

    except argparse.ArgumentError:
        parser.print_help()
        sys.exit(1)

    except Exception as e:
        print('Error:', str(e))
        sys.exit(2)

    else:
        sys.exit(0)
