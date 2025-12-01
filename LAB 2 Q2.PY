from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64


def aes_encrypt(plaintext, key_hex):
    """
    Encrypt using AES-128 in CBC mode
    """
    # Convert hex key to bytes (32 hex chars = 16 bytes)
    key = bytes.fromhex(key_hex)

    # Create cipher with random IV (Initialization Vector)
    cipher = AES.new(key, AES.MODE_CBC)

    # Pad and encrypt
    plaintext_bytes = plaintext.encode('utf-8')
    padded_data = pad(plaintext_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)

    # Return IV + ciphertext (both are needed for decryption)
    iv_ciphertext = cipher.iv + ciphertext
    return base64.b64encode(iv_ciphertext).decode('utf-8')


def aes_decrypt(ciphertext_b64, key_hex):
    """
    Decrypt AES-128 ciphertext
    """
    # Convert hex key to bytes
    key = bytes.fromhex(key_hex)

    # Decode base64
    iv_ciphertext = base64.b64decode(ciphertext_b64)

    # Extract IV (first 16 bytes) and ciphertext
    iv = iv_ciphertext[:AES.block_size]
    ciphertext = iv_ciphertext[AES.block_size:]

    # Create cipher and decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)

    # Remove padding
    plaintext_bytes = unpad(padded_plaintext, AES.block_size)

    return plaintext_bytes.decode('utf-8')


# Main execution
key = "0123456789ABCDEF0123456789ABCDEF"
message = "Sensitive Information"

print("AES-128 Encryption/Decryption")
print("=" * 40)
print(f"Key (32 hex chars): {key}")
print(f"Message: {message}")

# Encrypt
encrypted = aes_encrypt(message, key)
print(f"\nEncrypted (base64):")
print(encrypted)

# Decrypt
decrypted = aes_decrypt(encrypted, key)
print(f"\nDecrypted: {decrypted}")
print(f"Verification: {message == decrypted}")