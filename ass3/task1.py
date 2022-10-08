from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16
BYTE_FORMAT = 'ASCII'

def get_a_b(p: int) -> int:
  return random.randint(0, p)

def get_A_B(p: int, g: int, a_b:int) -> int:
  return pow(g, a_b, p)

def encrypt(msg: str, A_B: int, a_b: int, p: int, IV: bytes) -> bytes:
  s = pow(A_B, a_b, p)
  hasher = SHA256.new(bytes(s))
  key = hasher.digest()
  cipherer = AES.new(key, AES.MODE_CBC, IV)
  return cipherer.encrypt(pad(msg.encode(BYTE_FORMAT), BLOCK_SIZE))

def decrypt(cipher: bytes, A_B: int, a_b: int, p:int, IV: bytes) -> str:
  s = pow(A_B, a_b, p)
  hasher = SHA256.new(bytes(s))
  key = hasher.digest()
  cipherer = AES.new(key, AES.MODE_CBC, IV)
  msg = cipherer.decrypt(cipher)
  return msg.decode(BYTE_FORMAT)

def main():
  alice_IV = get_random_bytes(BLOCK_SIZE)
  bob_IV = get_random_bytes(BLOCK_SIZE)
  # task1 part 1
  p = 37
  g = 5
  a = get_a_b(p)
  b = get_a_b(p)
  A = get_A_B(p, g, a)
  B = get_A_B(p, g, b)
  c0 = encrypt('Hi Bob!', A, a, p, alice_IV)
  c1 = encrypt('Hi Alice!', B, b, p, bob_IV)
  print(c0, c1)
  m_from_bob = decrypt(c0, B, a, p, bob_IV)
  m_from_alice = decrypt(c1, B, a, p, alice_IV)
  print(m_from_alice, m_from_bob)
  # task1 part2


if __name__ == '__main__':
  main()