#!/usr/bin/env python3
import secrets
import hashlib
from time import time

class NcPowser:
    def __init__(self, difficulty=6, prefix_length=16):
        self.difficulty = difficulty
        self.prefix_length = prefix_length

    def get_challenge(self):
        return secrets.token_urlsafe(self.prefix_length)[:self.prefix_length].replace('-', 'b').replace('_', 'a')

    def verify_hash(self, prefix, answer):
        h = hashlib.sha256()
        h.update((prefix + answer).encode())
        return h.hexdigest().startswith('0' * self.difficulty)

if __name__ == '__main__':
    powser = NcPowser()
    prefix = powser.get_challenge()
    print(f'Send a suffix that: sha256("{prefix}" + ?).hex() == "000000..."')
    if not powser.verify_hash(prefix, input("Suffix: ")):
        exit(1)