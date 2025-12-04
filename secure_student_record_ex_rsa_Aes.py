# College Secure Grade Transmission
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def rsa_encrypt_simple(m, e, n):
    return pow(m, e, n)

def rsa_decrypt_simple(c, d, n):
    return pow(c, d, n)

print("=== College Secure Grade Transmission ===")
print("Step 1: RSA to exchange AES key")
print("Step 2: AES to encrypt message\n")

# RSA keys (simple numbers for demo)
n = 3233  # public key n
e = 17    # public exponent
d = 2753  # private exponent

# Generate random AES key
aes_key = get_random_bytes(16)
print(f"AES Key (hex): {aes_key.hex()}")

# Encrypt AES key with RSA
aes_key_int = int.from_bytes(aes_key, byteorder='big')
encrypted_key = rsa_encrypt_simple(aes_key_int, e, n)
print(f"Encrypted AES key (RSA): {encrypted_key}")

# AES encryption
message = input("\nEnter student grade record (e.g., 'John Doe: A, Math: B+'): ")
cipher_aes = AES.new(aes_key, AES.MODE_CBC)
iv = cipher_aes.iv
encrypted_msg = cipher_aes.encrypt(pad(message.encode(), AES.block_size))
print(f"IV (hex): {iv.hex()}")
print(f"Encrypted message (base64): {base64.b64encode(encrypted_msg).decode()}")

# Decryption demo
print("\n--- Decryption Side (Teacher) ---")
decrypted_key_int = rsa_decrypt_simple(encrypted_key, d, n)
decrypted_aes_key = decrypted_key_int.to_bytes(16, byteorder='big')
cipher_aes_dec = AES.new(decrypted_aes_key, AES.MODE_CBC, iv)
decrypted_msg = unpad(cipher_aes_dec.decrypt(encrypted_msg), AES.block_size)
print(f"Decrypted message: {decrypted_msg.decode()}")