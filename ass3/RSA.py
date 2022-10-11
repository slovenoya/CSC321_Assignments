from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime

LENGTH = 37

def get_prime(length: int) -> int:
  return getPrime(length)

def inverse_mod(e: int, phi: int) -> int:
  phi_current = phi
  while (phi_current + 1) % e != 0:
    phi_current += phi
  return (phi_current + 1) // e

def generate_keys(e:int, length: int) -> 'tuple[int, int]':
  p = get_prime(length)
  q = get_prime(length)
  n = p * q
  phi = (p - 1) * (q - 1)
  d = inverse_mod(e, phi)
  return (d, n)

def RSA_encrypt(public_key: 'tuple[int, int]', message: bytes) -> bytes:
  cipher = bytearray()
  e, n = public_key
  for byte in message: 
    C = pow(byte, e, n)
    cipher += C.to_bytes(LENGTH, 'big')
  return bytearray(cipher)

def RSA_decrypt(cipher: bytes, private_key: int, public_key: 'tuple[int, int]') -> bytes:
  message = bytes()
  e, n = public_key
  for i in range(len(cipher) // LENGTH):
    C = int.from_bytes(cipher[i*LENGTH : i*LENGTH + LENGTH], 'big')
    M = pow(C, private_key, n)
    message += M.to_bytes(1, 'big')
  return message

def main():
  e = 65537
  private_key, n = generate_keys(e, LENGTH)
  public_key = (e, n)
  cipher = RSA_encrypt(public_key, 'hello'.encode('ASCII'))
  print(RSA_decrypt(cipher, private_key, public_key))

if __name__ == '__main__':
  main()
