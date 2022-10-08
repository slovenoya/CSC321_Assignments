from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BLOCKSIZE = 16
p = 37
g = 5
a = random.randint(0, 16)
b = random.randint(0, 16)
hasher = SHA256.new()

def alice_send_A():
  A = pow(g, a, p)
  return A

def bob_send_B():
  B = pow(g, b, p)
  return B

def alice_encrypt(msg, B):
  s = pow(B, a, p)
  hasher.update(s)
  key = hasher.digest()
  cipherer = AES.new(key, AES.MODE_CBC, get_random_bytes(BLOCKSIZE))
  cipher = cipherer.encrypt(pad(msg, BLOCKSIZE))
  return cipher

def bob_encrypt(msg, A):
  s = pow(A, a, p)
  hasher.update(s)
  key = hasher.digest()
  cipherer = AES.new(key, AES.MODE_CBC, get_random_bytes(BLOCKSIZE))
  cipher = cipherer.encrypt(pad(msg, BLOCKSIZE))
  return cipher

def main():
  alice_encrypt('hi bob', bob_send_B())
  bob_encrypt('hi bob', alice_send_A())

if __name__ == '__main__':
  main()