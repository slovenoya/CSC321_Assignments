from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime

LENGTH = 2048

def get_prime(length: int) -> int:
  return getPrime(length)

def main():
  e = 65537
  n = get_prime(LENGTH)
  m = random.randint(0, n-1)
  

if __name__ == '__main__':
  main()