# Ryan Zhang
# Assignment 2 
# Cypher a file with EBC and CBC encryption
# Use pycryptodome to encrypto sections of message. 
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE=16
BMP_HEADER_SIZE = 54
KEY = get_random_bytes(BLOCK_SIZE)
IV = get_random_bytes(BLOCK_SIZE)

def encrypt_data_EBC(data:bytes) -> bytes:
  bmp_header = data[0:BMP_HEADER_SIZE]
  bmp_body = data[BMP_HEADER_SIZE:]
  pad_bmp_body = pad(bmp_body, BLOCK_SIZE, 'pkcs7')
  EBC_cipher = AES.new(KEY, AES.MODE_ECB)
  cipher = bmp_header
  for i in range(len(pad_bmp_body) // BLOCK_SIZE):
    cipher = cipher + EBC_cipher.encrypt(pad_bmp_body[i*BLOCK_SIZE : (i + 1)*(BLOCK_SIZE)])
  return cipher
  
def encrypt_data_CBC(data:bytes) -> bytes:
  data_header = data[0:BMP_HEADER_SIZE]
  data_body = data[BMP_HEADER_SIZE:]
  pad_data_body = pad(data_body, BLOCK_SIZE, 'pkcs7')
  cipher = data_header
  cipher_in = IV
  for i in range(len(pad_data_body) // BLOCK_SIZE):
    CBC_cipher = AES.new(KEY, AES.MODE_CBC, cipher_in)
    cipher_in = CBC_cipher.encrypt(pad_data_body[i*BLOCK_SIZE : (i + 1)*(BLOCK_SIZE)])
    cipher = cipher + cipher_in
  return cipher

if __name__ == '__main__':
  with open('cp-logo.bmp', 'rb') as read_from:
    data = read_from.read()
    encrypt_data_EBC(data)
    with open('EBC.bmp', 'wb') as write_to:
      encrypted = encrypt_data_EBC(data)
      write_to.write(encrypted)
    with open('CBC.bmp', 'wb') as write_to:
      encrypted = encrypt_data_CBC(data)
      write_to.write(encrypted)