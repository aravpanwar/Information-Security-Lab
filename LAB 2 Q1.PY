from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64

def des_encrypt(plaintext, key):
    # DES requires 8-byte key
    key = key.encode('utf-8')
    if len(key) < 8:
        # Pad key if too short
        key = key.ljust(8, b'\0')
    elif len(key) > 8:
        # Truncate if too long
        key = key[:8]

    # Create DES cipher in ECB mode (simplest)
    cipher = DES.new(key, DES.MODE_ECB)

    # Pad message to multiple of 8 bytes
    plaintext_bytes = plaintext.encode('utf-8')
    padded_data = pad(plaintext_bytes, DES.block_size)

    # Encrypt
    ciphertext = cipher.encrypt(padded_data)

    # Return as base64 for readability
    return base64.b64encode(ciphertext).decode('utf-8')

def des_decrypt(ciphertext_b64, key):
    # Prepare key (same as encryption)
    key = key.encode('utf-8')
    if len(key) < 8:
        key = key.ljust(8, b'\0')
    elif len(key) > 8:
        key = key[:8]

    # Create DES cipher
    cipher = DES.new(key, DES.MODE_ECB)

    # Decode base64 and decrypt
    ciphertext = base64.b64decode(ciphertext_b64)
    padded_plaintext = cipher.decrypt(ciphertext)

    # Remove padding
    plaintext_bytes = unpad(padded_plaintext, DES.block_size)

    return plaintext_bytes.decode('utf-8')

# Main
key = "A1B2C3D4"
message = "Confidential Data"

print("DES Encryption/Decryption")
print("=" * 30)
print(f"Key: {key}")
print(f"Message: {message}")

# Encrypt
encrypted = des_encrypt(message, key)
print(f"\nEncrypted (base64): {encrypted}")

# Decrypt
decrypted = des_decrypt(encrypted, key)
print(f"Decrypted: {decrypted}")
print(f"Verification: {message == decrypted}")