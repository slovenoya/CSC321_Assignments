from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16
KEY_SIZE = 256
BYTE_FORMAT = 'ASCII'

def get_a_b(p: int) -> int:
  return random.randint(2, p-2)

def get_A_B(p: int, g: int, a_b:int) -> int:
  return pow(g, a_b, p)

def encrypt(msg: str, A_B: int, a_b: int, p: int, IV: bytes) -> bytes:
  s = pow(A_B, a_b, p)
  hasher = SHA256.new()
  byte_s = s.to_bytes(KEY_SIZE, 'big')
  hasher.update(byte_s)
  key = hasher.digest()
  cipherer = AES.new(key, AES.MODE_CBC, IV)
  return cipherer.encrypt(pad(msg.encode(BYTE_FORMAT), BLOCK_SIZE))

def decrypt(cipher: bytes, A_B: int, a_b: int, p:int, IV: bytes) -> str:
  s = pow(A_B, a_b, p)
  hasher = SHA256.new()
  byte_s = s.to_bytes(KEY_SIZE, 'big')
  hasher.update(byte_s)
  key = hasher.digest()
  cipherer = AES.new(key, AES.MODE_CBC, IV)
  msg = cipherer.decrypt(cipher)
  return unpad(msg, BLOCK_SIZE).decode(BYTE_FORMAT)


# s is a special integer that is predicted by the hacker, with special p, g values, s is predictable. 
def hack_decrypt(cipher: bytes, s:int, IV: bytes):
  hasher = SHA256.new()
  byte_s = s.to_bytes(256, 'big')
  hasher.update(byte_s)
  key = hasher.digest()
  cipherer = AES.new(key, AES.MODE_CBC, IV)
  msg = cipherer.decrypt(cipher)
  return unpad(msg, BLOCK_SIZE).decode(BYTE_FORMAT)

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
  c0 = encrypt('Hi Bob!', B, a, p, alice_IV)
  c1 = encrypt('Hi Alice!', A, b, p, bob_IV)
  m_from_bob = decrypt(c0, B, a, p, alice_IV)
  m_from_alice = decrypt(c1, B, a, p, bob_IV)
  print(m_from_alice, m_from_bob)

  # task1 part2
  p = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
  g = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
  a = get_a_b(p)
  b = get_a_b(p)
  A = get_A_B(p, g, a)
  B = get_A_B(p, g, b)
  c0 = encrypt('Hi Bob!', B, a, p, alice_IV)
  c1 = encrypt('Hi Alice!', A, b, p, bob_IV)
  m_from_bob = decrypt(c0, B, a, p, alice_IV)
  m_from_alice = decrypt(c1, B, a, p, bob_IV)
  print(m_from_alice, m_from_bob)

  # task2 part A
  a = get_a_b(p)
  b = get_a_b(p)
  A = p
  B = p
  c0 = encrypt('Hi Bob!', B, a, p, alice_IV)
  c1 = encrypt('Hi Alice!', A, b, p, bob_IV)
  # when we change A, B to p, s must be zero
  m_from_bob = hack_decrypt(c0, 0, alice_IV)
  m_from_alice = hack_decrypt(c1, 0, bob_IV)
  print(m_from_alice, m_from_bob)

  # task2 part B attack case g = 1
  g = 1
  a = get_a_b(p)
  b = get_a_b(p)
  A = get_A_B(p, g, a)
  B = get_A_B(p, g, b)
  c0 = encrypt('Hi Bob!', B, a, p, alice_IV)
  c1 = encrypt('Hi Alice!', A, b, p, bob_IV)
  m_from_bob = hack_decrypt(c0, 1, alice_IV)
  m_from_alice = hack_decrypt(c1, 1, bob_IV)
  print(m_from_alice, m_from_bob)

  # task2 B attack case g = p
  g = p
  a = get_a_b(p)
  b = get_a_b(p)
  A = get_A_B(p, g, a)
  B = get_A_B(p, g, b)
  c0 = encrypt('Hi Bob!', B, a, p, alice_IV)
  c1 = encrypt('Hi Alice!', A, b, p, bob_IV)
  m_from_bob = hack_decrypt(c0, 0, alice_IV)
  m_from_alice = hack_decrypt(c1, 0, bob_IV)
  print(m_from_alice, m_from_bob)

  # task2 B attack case g = p - 1
  g = p - 1
  a = get_a_b(p)
  b = get_a_b(p)
  A = get_A_B(p, g, a)
  B = get_A_B(p, g, b)
  c0 = encrypt('Hi Bob!', B, a, p, alice_IV)
  c1 = encrypt('Hi Alice!', A, b, p, bob_IV)

  # s is either 1 or p-1, when both a and b are odd, s is p-1, otherwise 1

  try: 
    m_from_bob = hack_decrypt(c0, 1, alice_IV)
  except ValueError:
    m_from_bob = hack_decrypt(c0, p-1, alice_IV)
  try:
    m_from_alice = hack_decrypt(c1, 1, bob_IV)
  except ValueError:
    m_from_alice = hack_decrypt(c1, p-1, bob_IV)

  print(m_from_alice, m_from_bob)

if __name__ == '__main__':
  main()