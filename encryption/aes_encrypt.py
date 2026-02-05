from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def aes_encrypt(data):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return ciphertext
