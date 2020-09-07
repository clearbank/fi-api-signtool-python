import sys
import argparse
import hashlib
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding


class RunResult:
    def __init__(self):
        self.UTF8EncodedData = ""
        self.HashedData = ""
        self.SignedData = ""
        self.EncodedData = ""


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


def DoHash(text):
    print("RunHash")
    print('Using:', text)

    encoded_bytes = encode_text(text)
    print('UTF8EncodedData:',  bytes_to_text(encoded_bytes))

    hashed_text = hash_text(encoded_bytes)
    print('HashedData (SHA256):', hash_to_text(hashed_text))

    return hashed_text


def DoSign(arguments, hashed_text):
    print("RunSign")
    print("Using:", hash_to_text(hashed_text))

    signed_bytes = sign_hash(hashed_text.digest(), arguments.keyfile)
    print('SignedData:', bytes_to_text(signed_bytes))

    return signed_bytes


def DoEncode(signed_bytes):
    print("RunEncode")
    print("Using:", bytes_to_text(signed_bytes))

    encoded_text = encode_bytes(signed_bytes)
    print('EncodedData:', encoded_text.decode('utf-8').replace("\n", ""))

    return encoded_text


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Hash, Sign and Encode text for FI.API')
    parser.add_argument('command', action='store')
    parser.add_argument('-t', '--text', action='store', required=False)
    parser.add_argument('-f', '--file', action='store', required=False)
    parser.add_argument('-k', '--keyfile', action='store', required=True)

    try:
        arguments = parser.parse_args()

        text = arguments.text

        if not text:
            if arguments.file:
                with open(arguments.file) as file:
                    text = file.read()

        if not text:
            raise Exception('Must specify text or file')

        command = arguments.command.lower()

        if (command == "hashsignencode"):
            hashed_text = DoHash(text)

            print()
            signed_bytes = DoSign(arguments, hashed_text)

            print()
            DoEncode(signed_bytes)

        elif (command == "hash"):
            DoHash(text)

        elif (command == "sign"):
            print("Not yet implemented")
            #DoSign
            
        elif (command == "encode"):
            print("Not yet implemented")
            #DoEncode
        
        else:
            raise Exception("Invalid command - " + arguments.command)

    except argparse.ArgumentError:
        parser.print_help()
        sys.exit(1)

    except Exception as e:
        print('Error:', str(e))
        sys.exit(2)

    else:
        sys.exit(0)
