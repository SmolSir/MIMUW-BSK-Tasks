from pwn import *
from math import gcd
from functools import reduce
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from utils import LcgPrng, lcg_encrypt, xor, split_by, ae_encrypt, ae_decrypt

SERVER_NAME = 'cryptotask2022.tailcall.net'
SERVER_PORT = 30006

def solve_task_1():
    print('-- solve_task_1 --')
    try:
        # connect to the server
        connection = remote(SERVER_NAME, SERVER_PORT)

        # receive the welcome message
        connection.recvuntil(b'>')

        # 1) Warmup
        connection.sendline(b'1')

        # receive m = ...
        connection.recvuntil(b'm=')
        m = int(connection.recvuntil(b'\n', drop=True))

        # receive 'base> ' & send base
        b = connection.recvuntil(b'base> ')
        connection.sendline(str(m - 1).encode())

        print('Guessing...')

        for i in range(1000):
            # send guess
            connection.sendline(b'1')

        for i in range(1000):
            # receive 'guess> '
            connection.recvuntil(b'guess> ')


        # receive & return the flag
        flag = connection.recvline().decode().strip()
        connection.close()
        return flag

    except Exception as exception:
        print(exception)


def solve_task_2():
    print('-- solve_task_2 --')
    try:
        # connect to the server
        connection = remote(SERVER_NAME, SERVER_PORT)

        # receive the welcome message
        connection.recvuntil(b'>')

        # 2) Stream cipher
        connection.sendline(b'2')

        # receive the lcg encrypted flag
        lcg_flag = connection.recvuntil(b'\nbye!', drop=True).decode().strip()
        connection.close()

        # split the lcg_flag into hex representation bytes
        lcg_flag = split_by(lcg_flag, 2)
        lcg_flag = [int(x, base=16) for x in lcg_flag]

        # to reverse the encryption, we need to find the server's key.
        # start by finding its next() value's first 5 bytes (key_prefix)
        flag_prefix = split_by(binascii.hexlify(b'flag{').decode(), 2)
        flag_prefix = [int(x, base=16) for x in flag_prefix]

        key_prefix = xor(flag_prefix, lcg_flag)

        # the remaining 3 bytes have to be guessed, for that we:
        # 1) compute the modinv of a & m, ensuring gcd(a, m) == 1
        assert gcd(LcgPrng.a, LcgPrng.m) == 1
        modinv = pow(LcgPrng.a, -1, LcgPrng.m)

        # 2) define a helper function to check if the decrypted flag is of
        #    correct length, ends with '}', starts with b'flag{' & contains
        #    only printable ASCII characters (codes 32 - 126)
        def check_guess_flag(flag):
            return len(flag) == len(lcg_flag) and \
                   flag[-1] == ord('}') and \
                   flag[ : 5] == b'flag{' and \
                   all(32 <= byte <= 126 for byte in flag)

        # 3) iterate through the possibilities
        print('Guessing...')
        for guess in range(2 ** 24):
            key_next = key_prefix + guess.to_bytes(3, 'little')

            # convert to integer (reverse byte order because LcgPrng's
            # next_bytes() method returns little endian)
            key_next = int.from_bytes(key_next, 'little')

            # now we use inverse modulo to find the original key
            key = ((key_next - LcgPrng.c) % LcgPrng.m) * modinv

            # the only thing left is to check whether the guessed key decodes
            # the encrypted flag
            guess_flag = lcg_encrypt(key, lcg_flag)
            if check_guess_flag(guess_flag):
                return guess_flag.decode()

    except Exception as exception:
        print(exception)


def solve_task_3():
    print('-- solve_task_3 --')
    try:
        # connect to the server
        connection = remote(SERVER_NAME, SERVER_PORT)

        # receive the welcome message
        connection.recvuntil(b'>')

        # 3) Block cipher (easier)
        connection.sendline(b'3')

        # receive 'pt> ' & send plaintext
        connection.recvuntil(b'pt> ')
        connection.sendline(b'')

        # receive 'ct> ' & send cyphertext
        connection.recvuntil(b'ct> ')
        connection.sendline(b'')

        # receive response (encrypted flag) & drop the newline byte
        response = connection.recvline().decode().strip()
        connection.close()

        return response

    except Exception as exception:
        print(exception)



def solve_task_4():
    print('-- solve_task_4 --')
    pass


def main():
    # get the flags
    task_names = [
        "1) Warmup",
        "2) Stream cipher",
        "3) Block cipher (easier)",
        "4) Block cipher (hard)",
    ]
    flags = [
        solve_task_1(),
        solve_task_2(),
        solve_task_3(),
        solve_task_4(),
    ]

    # print the flags
    print('\nThe following flags were captured:')

    for name, flag in zip(task_names, flags):
        print(name, '--', flag)


# run the script
main()
