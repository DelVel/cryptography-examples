import os
from base64 import b64encode, b64decode

import clipboard
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

private_key_filename = 'p.key'
public_key_filename = 'p.pub'


def main():
    if not (os.path.exists(private_key_filename) and os.path.exists(public_key_filename)):
        create_keys()
    while True:
        inp = input("1: encrypt, 2: decrypt, q: quit: ")
        if inp == '1':
            encrypt_message()
        elif inp == '2':
            decrypt_message()
        elif inp == 'q':
            break


def encrypt_message():
    with open(public_key_filename, 'rb') as f:
        public_key = PKCS1_OAEP.new(RSA.importKey(f.read()))
    input_byte = input('Encrypt: ').encode('UTF-8')
    message = b64encode(public_key.encrypt(input_byte)).decode('UTF-8')
    print(message)
    print('Copied to clipboard.')
    clipboard.copy(message)


def decrypt_message():
    with open(private_key_filename, 'rb') as f:
        private_key = PKCS1_OAEP.new(RSA.importKey(f.read()))
    input_string = input('Decrypt (enter to use from clipboard): ')
    if not input_string:
        print('Pasted from clipboard.')
        input_string = clipboard.paste()
    print(private_key.decrypt(b64decode(input_string.encode('UTF-8'))).decode('UTF-8'))


def create_keys():
    key = RSA.generate(4096)
    private_key = key.export_key('PEM')
    with open(private_key_filename, 'wb') as f:
        f.write(private_key)
    public_key = key.publickey().exportKey('PEM')
    with open(public_key_filename, 'wb') as f:
        f.write(public_key)


if __name__ == '__main__':
    main()
