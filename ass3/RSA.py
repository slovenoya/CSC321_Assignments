from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime

LENGTH = 37
BYTE_ORDER = 'big'

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
    cipher += C.to_bytes(LENGTH, BYTE_ORDER)
  return bytearray(cipher)

def RSA_decrypt(cipher: bytes, private_key: int, public_key: 'tuple[int, int]') -> bytes:
  message = bytes()
  e, n = public_key
  for i in range(len(cipher) // LENGTH):
    C = int.from_bytes(cipher[i*LENGTH : i*LENGTH + LENGTH], BYTE_ORDER)
    M = pow(C, private_key, n)
    message += M.to_bytes(1, BYTE_ORDER)
  return message

def main():
  # part A
  e = 65537
  # get private key (d) and the other part of public key 
  private_key, n = generate_keys(e, LENGTH)
  public_key = (e, n)
  #get a cipher
  cipher = RSA_encrypt(public_key, 'hello'.encode('ASCII'))
  #decrypt the cipher
  print('decrypted message: ', RSA_decrypt(cipher, private_key, public_key))

  #try another message
  cipher = RSA_encrypt(public_key, 'some important message'.encode('ASCII'))
  print('decrypted message: ', RSA_decrypt(cipher, private_key, public_key))

  #part B
  

if __name__ == '__main__':
  main()
