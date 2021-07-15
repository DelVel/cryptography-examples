import multiprocessing
import os
from base64 import b64encode, b64decode
from multiprocessing import Pool

import clipboard
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

private_key_filename = 'p.key'
public_key_filename = 'p.pub'
outfile = 'file.res'
pool = None


def main():
    if not (os.path.exists(private_key_filename) and os.path.exists(public_key_filename)):
        create_keys()
    while True:
        inp = input("1: encrypt, 2: decrypt, 3: encrypt file, 4: decrypt file, q: quit: ")
        if inp == '1':
            encrypt_plaintext()
        elif inp == '2':
            try:
                decrypt_plaintext()
            except Exception as e:
                print(e)
        elif inp == '3':
            try:
                encrypt_file()
            except Exception as e:
                print(e)
        elif inp == '4':
            try:
                decrypt_file()
            except Exception as e:
                print(e)
        elif inp == 'q':
            break


def encrypt_plaintext():
    message = input('Encrypt: ')
    encrypted = encrypt_byte(message.encode('UTF-8')).decode('UTF-8')
    print(encrypted)
    clipboard.copy(encrypted)
    print('Copied to clipboard.')


def decrypt_plaintext():
    encrypted = input('Decrypt (enter to use from clipboard): ')
    if not encrypted:
        encrypted = clipboard.paste()
    decrypted = decrypt_byte(encrypted.encode('UTF-8'))
    print(decrypted.decode('UTF-8'))


def encrypt_file():
    filename = input('Filename: ')
    encrypted_list = []
    block = 470
    with open(filename, 'rb') as f:
        file_read = f.read(block)
        while file_read:
            encrypted_list.append(encrypt_byte(file_read).decode('UTF-8'))
            file_read = f.read(block)
    encrypted_message = ','.join(encrypted_list)
    print(encrypted_message)
    clipboard.copy(encrypted_message)
    print('Copied to clipboard.')


def decrypt_file():
    encrypted = input('Decrypt (enter to use from clipboard): ')
    if not encrypted:
        encrypted = clipboard.paste()
    encrypted_list = encrypted.split(',')
    private_key = read_binary(private_key_filename)
    iterable = list(map(lambda x: (x, private_key), encrypted_list))
    mapped = get_pool().map(func=decrypt_runner, iterable=iterable)
    decrypted = b''.join(mapped)
    with open(outfile, 'wb') as f:
        f.write(decrypted)
    print(f'Exported to `{outfile}`.')


def encrypt_byte(input_byte):
    public_key = obtain_public_key()
    return b64encode(public_key.encrypt(input_byte))


def decrypt_byte(input_byte):
    private_key = obtain_private_key()
    return private_key.decrypt(b64decode(input_byte))


def decrypt_runner(x):
    private_key = PKCS1_OAEP.new(RSA.importKey(x[1]))
    return private_key.decrypt(b64decode(x[0]))


def obtain_public_key():
    binary = read_binary(public_key_filename)
    public_key = PKCS1_OAEP.new(RSA.importKey(binary))
    return public_key


def obtain_private_key():
    binary = read_binary(private_key_filename)
    private_key = PKCS1_OAEP.new(RSA.importKey(binary))
    return private_key


def read_binary(filename):
    with open(filename, 'rb') as f:
        read = f.read()
    return read


def create_keys():
    key = RSA.generate(4096)
    private_key = key.export_key('PEM')
    with open(private_key_filename, 'wb') as f:
        f.write(private_key)
    public_key = key.publickey().exportKey('PEM')
    with open(public_key_filename, 'wb') as f:
        f.write(public_key)


def get_pool():
    global pool
    if pool is None:
        pool = Pool(multiprocessing.cpu_count())
    return pool


if __name__ == '__main__':
    main()
