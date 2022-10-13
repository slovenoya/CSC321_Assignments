import binascii
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from time import time

def find_crash(digest_len:int):
  start = time()
  hasher = SHA256.new()
  while True:
    hasher.update(get_random_bytes(1))
    m1 = hasher.digest()
    m1 = int.from_bytes(m1, 'big')
    m1 = bin(m1)[:digest_len]

    hasher.update(get_random_bytes(1))
    m2 = hasher.digest()
    m2 = int.from_bytes(m2, 'big')
    m2 = bin(m2)[:digest_len]

    if m1 == m2:
      end = time()
      print(f'{digest_len} bits takes {end - start} second to clash')
      return

def main():
  hasher = SHA256.new()
  hasher.update(b'1')
  print(hasher.digest())
  hasher.update(b'2')
  print(hasher.digest())
  hasher.update(b'3')
  print(hasher.digest())

  for i in range(8, 50, 2):
    find_crash(i)

if __name__ == '__main__':
  main()