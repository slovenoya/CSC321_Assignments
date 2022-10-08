from ctypes.wintypes import HACCEL
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16
KEY = get_random_bytes(BLOCK_SIZE)
IV = get_random_bytes(BLOCK_SIZE)
CBC_cipher = AES.new(KEY, AES.MODE_CBC, IV)
CBC_cipher2 = AES.new(KEY, AES.MODE_CBC, IV)

def submit(msg:str) -> bytes:
  msg = 'userid=456;userdata=' + msg + ';session-id=31337'
  msg.replace('=','%3D')
  msg.replace(';','%3B')
  msg = pad(msg.encode('ASCII'), BLOCK_SIZE)
  return CBC_cipher.encrypt(msg)

def verify(cipher:bytes) -> bool:
  cipher = CBC_cipher2.decrypt(cipher)
  cipher = str(cipher)
  cipher = cipher.replace('%3B', ';')
  cipher = cipher.replace('%3D', '=')
  return ';admin=true;' in cipher

def hack(cipher:bytes) -> bytes:
  insertion = ';admin=true;'.encode('ASCII')
  insertion = pad(insertion, BLOCK_SIZE)
  message = CBC_cipher2.decrypt(cipher)
  xor_msg = bytearray()
  cipher_array = bytearray(cipher)
  for i in range(len(insertion)):
    xor_msg.append(insertion[i] ^ message[i + BLOCK_SIZE])
  for i in range(BLOCK_SIZE):
    cipher_array[i] = cipher_array[i] ^ xor_msg[i]
  return bytes(cipher_array)

if __name__ == '__main__':
  print(verify(submit('hello')))
  print(verify(submit(';admin=true;')))
  print(verify(hack(submit('hello'))))