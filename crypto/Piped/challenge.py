from sage.all import *
load('utils.sage')
load('Signature.sage')

import json
import sys, os
from secret import THEFLAG
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes


def encrypt(k, m):
	key = sha256(long_to_bytes(k)).digest()
	iv = os.urandom(16)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	enc_flag = cipher.encrypt(pad(m, 16)).hex()
	return iv.hex() + enc_flag


if __name__ == "__main__":
	print("Welcome to THEFLAG complex.")

	N = 3
	l = 1337
	sig = Signature(N, l)

	print("Here's your public key, use it to wander around, but not where we store THEFLAG:")
	print(f'Pubkey: {tuple(sig.pk)}')
	print()

	for _ in range(1337):
		try:
			option = input('Wanna take free signatures (Y/n)? ').upper()
			if option == 'Y':
				m = random_vector(ZZ, N, x=-l, y=l)
				s = sig.sign(m)
				print(f'Message: {m}')
				print(f'Signature: {s}')
			elif option =='N':
				print('If you have the key you can see THEFLAG closer!')
				m = random_vector(ZZ, N, x=-l, y=l)
				ck = json.loads(input('Show your key: '))
				ck = Matrix(ZZ, ck)
				ss = sig.sign(m)
				if ss == babai(ck, ck.gram_schmidt()[0], m):
					print("Come inside! THEFLAG is very well protected here!")
					key = abs(hash(tuple(sig.sk.row(0))))
					print(f'THEFLAG: {encrypt(key, THEFLAG)}')
			else:
				sys.exit()
		except:
			sys.exit()


