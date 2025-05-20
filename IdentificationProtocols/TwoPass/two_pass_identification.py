from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

def encrypt_message(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.IV
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv + ciphertext

def decrypt_message(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return plaintext.decode()
