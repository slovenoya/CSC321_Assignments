from ctypes.wintypes import BYTE
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime

LENGTH = 16
IV_LENGTH = 16
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

def RSA_CBC_encrypt(public_key: 'tuple[int, int]', private_key: int, message:bytes, CBC_key_RSA:bytes, IV: bytes) -> bytes:
  hasher = SHA256.new()
  CBC_key = RSA_decrypt(CBC_key_RSA, private_key, public_key)
  hasher.update(CBC_key)
  CBC_key = hasher.digest()
  cipherer = AES.new(CBC_key, AES.MODE_CBC, IV)
  return cipherer.encrypt(pad(message, IV_LENGTH))

def RSA_CBC_decrypt(CBC_key: int, cipher: bytes, IV: bytes) -> bytes:
  hasher = SHA256.new()
  hasher.update(CBC_key.to_bytes(LENGTH, BYTE_ORDER))
  CBC_key = hasher.digest()
  cipherer = AES.new(CBC_key, AES.MODE_CBC, IV)
  message = cipherer.decrypt(cipher)
  return unpad(message, IV_LENGTH)

def hack_decrypt(cipher: bytes, IV: bytes) -> bytes:
  CBC_key = 1
  hasher = SHA256.new()
  hasher.update(CBC_key.to_bytes(1, BYTE_ORDER))
  CBC_key = hasher.digest()
  cipherer = AES.new(CBC_key, AES.MODE_CBC, IV)
  message = cipherer.decrypt(cipher)
  return unpad(message, IV_LENGTH)

def hack() -> bytes:
  return int.to_bytes(1, LENGTH, BYTE_ORDER)

def main():
  # part A
  e = 65537
  # get private key (d) and the other part of public key 
  private_key, n = generate_keys(e, LENGTH)
  public_key = (e, n)
  #get a cipher
  cipher = RSA_encrypt(public_key, 'hello, alice'.encode('ASCII'))
  #decrypt the cipher
  print('decrypted message: ', RSA_decrypt(cipher, private_key, public_key))

  #try another message
  cipher = RSA_encrypt(public_key, 'some important message from bob'.encode('ASCII'))
  print('decrypted message: ', RSA_decrypt(cipher, private_key, public_key))

  #part B combine RSA and CBC
  alice_IV = get_random_bytes(IV_LENGTH)
  bob_CBC_key = get_random_bytes(LENGTH)
  bob_CBC_key_RSA = RSA_encrypt(public_key, bob_CBC_key)
  # alice send message and encrypt it with her private key and CBC key that is encoded in
  # bob's message that encrypted by her public key
  c0 = RSA_CBC_encrypt(public_key, private_key, 'hi, bob!'.encode('ASCII'), bob_CBC_key_RSA, alice_IV)
  # bob decode the cipher sent by alice

  # part B hacking
  bob_CBC_key_RSA = hack()
  c0 = RSA_CBC_encrypt(public_key, private_key, 'hi, bob!'.encode('ASCII'), bob_CBC_key_RSA, alice_IV)
  message = hack_decrypt(c0, alice_IV)
  print(f'message sent by Alice: {message}')
  
if __name__ == '__main__':
  main()
