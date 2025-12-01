from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import time

# Message to encrypt
message = "Performance Testing of Encryption Algorithms"
key = "A1B2C3D4"

# Convert to bytes
message_bytes = message.encode('utf-8')

# Test DES
des_key = key.encode('utf-8')
des_cipher = DES.new(des_key, DES.MODE_ECB)
padded_message = pad(message_bytes, DES.block_size)

start = time.time()
des_ciphertext = des_cipher.encrypt(padded_message)
des_encrypt_time = time.time() - start

start = time.time()
des_decipher = DES.new(des_key, DES.MODE_ECB)
des_decrypted = unpad(des_decipher.decrypt(des_ciphertext), DES.block_size)
des_decrypt_time = time.time() - start

# Test AES-256
aes_key = key.ljust(32, '0').encode('utf-8')
aes_cipher = AES.new(aes_key, AES.MODE_ECB)
padded_message = pad(message_bytes, AES.block_size)

start = time.time()
aes_ciphertext = aes_cipher.encrypt(padded_message)
aes_encrypt_time = time.time() - start

start = time.time()
aes_decipher = AES.new(aes_key, AES.MODE_ECB)
aes_decrypted = unpad(aes_decipher.decrypt(aes_ciphertext), AES.block_size)
aes_decrypt_time = time.time() - start

# Print results
print("DES Times:")
print(f"Encryption: {des_encrypt_time:.6f} seconds")
print(f"Decryption: {des_decrypt_time:.6f} seconds")
print(f"Total: {des_encrypt_time + des_decrypt_time:.6f} seconds")
print()

print("AES-256 Times:")
print(f"Encryption: {aes_encrypt_time:.6f} seconds")
print(f"Decryption: {aes_decrypt_time:.6f} seconds")
print(f"Total: {aes_encrypt_time + aes_decrypt_time:.6f} seconds")