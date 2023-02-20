#!/usr/bin/env python3
from pathlib import Path
from socketserver import TCPServer, ThreadingMixIn, BaseRequestHandler
import string
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes, random
from Crypto.Util.number import getPrime

from utils import read_until, xor, lcg_encrypt, split_by, ae_encrypt, ae_decrypt
# from secrets import FLAG1, FLAG2, FLAG3, FLAG4
FLAG1, FLAG2, FLAG3, FLAG4 = 'flag{1}', 'flag{2}', 'flag{3}', 'flag{4}'

class ThreadedTCPServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True


class TCPHandler(BaseRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


    def read_line(self):
        return read_until(self.sock, b'\n').decode().strip()


    def read_line_hex(self):
        return bytes.fromhex(self.read_line())


    def send(self, text):
        self.sock.sendall(text.encode())


    def send_line_hex(self, data):
        self.sock.sendall((data.hex() + '\n').encode())


    def handle(self):
        self.sock = self.request
        print(f'{self.client_address} connected!')
        try:
            self.send('Welcome to the crypto task game!\n')
            self.send('''
Which challenge do you want to solve?
 1) Warmup
 2) Stream cipher
 3) Block cipher (easier)
 4) Block cipher (hard)
''')
            while True:
                self.send('> ')
                choice = self.read_line()
                if choice in ['1', '2', '3', '4']:
                    break
                self.send('???\n')

            if choice == '1':
                # A simple warmup challenge.
                self.warmup_chall()
            elif choice == '2':
                # Harder, but still easy.
                self.lcg_chall()
            elif choice == '3':
                # Entry level to the main challenge.
                self.ae_easy_chall()
            else:
                assert choice == '4'
                # The main challenge.
                # Remember the slide from the labs with GCM mode for
                # Authenticated Encryption? It's quite complex, but fortunately
                # we've found a simpler construction which achieves the same!
                self.ae_hard_chall()
            self.send('bye!\n')
        except (EOFError, ConnectionResetError):
            pass


    def finish(self):
        print(f'{self.client_address} disconnected!')


    # -------- Warmup challenge --------
    def warmup_chall(self):
        m = getPrime(1024)
        self.send(f'{m=}\n')
        points = 0
        try:
            self.send('base> ')
            base = int(self.read_line())
            if base < 2 or base >= m:
                self.send('???\n')
                return
            for _ in range(1000):
                self.send('guess> ')
                guess = int(self.read_line())
                exp = random.randrange(2, m - 1)
                rand = pow(base, exp, m)
                if rand == guess:
                    points += 1
            if points > 300:
                self.send(f'{FLAG1}\n')
        except ValueError:
            self.send('???\n')


    # -------- LCG challenge --------
    def lcg_chall(self):
        # key = random.randrange(0, 2**64)
        key = 17784302139744016438
        enc_data = lcg_encrypt(key, FLAG2.encode())
        self.send_line_hex(enc_data)


    # -------- AE challenge (easier) --------
    def ae_easy_chall(self):
        key = get_random_bytes(16)
        aes = AES.new(key, AES.MODE_ECB)
        while True:
            try:
                # Can you correctly sign any plaintext without the key?
                self.send('pt> ')
                pt = self.read_line_hex()
                self.send('ct> ')
                ct = self.read_line_hex()
                decrypted, sign_ok = ae_decrypt(aes, ct)
                if decrypted != pt:
                    self.send('you don\'t even know what you encrypted? sus.\n')
                elif not sign_ok:
                    self.send('hacker detected!\n')
                else:
                    # easier flag
                    self.send_line_hex(ae_encrypt(aes, FLAG3.encode()))
            except ValueError:
                self.send('???\n')

    # -------- AE challenge (hard) --------
    def ae_hard_chall(self):
        key = get_random_bytes(16)
        aes = AES.new(key, AES.MODE_ECB)
        while True:
            try:
                # Can you correctly sign any plaintext without the key?
                self.send('pt> ')
                pt = self.read_line_hex()
                self.send('ct> ')
                ct = self.read_line_hex()
                decrypted, sign_ok = ae_decrypt(aes, ct)
                if not sign_ok or decrypted != pt:
                    self.send('hacker detected!\n')
                elif decrypted == b'dej flage :3':
                    # hard flag
                    self.send_line_hex(ae_encrypt(aes, FLAG4.encode()))
                else:
                    # send some garbage, indistinguishable from encrypted flag
                    self.send_line_hex(ae_encrypt(aes, get_random_bytes(len(FLAG4.encode()))))
            except ValueError:
                self.send('???\n')


def main():
    PORT = 13371
    try:
        with ThreadedTCPServer(('0.0.0.0', PORT), TCPHandler) as server:
            print(f'Server started on port {PORT}')
            server.serve_forever()
    except KeyboardInterrupt: # Ctrl-C
        print('Exiting...')

if __name__ == '__main__':
    main()
