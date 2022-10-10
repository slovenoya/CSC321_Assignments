from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime

LENGTH = 16

def get_prime(length: int) -> int:
  return getPrime(length)

def inverse_mod(n: bytes, e: bytes, phi: bytes) -> bytes:
  pass

def generate_keys(e:bytes, length: int) -> 'tuple[int, int]':
  p = get_prime(length)
  q = get_prime(length)
  n = p * q
  phi = (p - 1) * (q - 1)
  d = 0
  return (n, d)

def main():
  e = 65537

if __name__ == '__main__':
  main()