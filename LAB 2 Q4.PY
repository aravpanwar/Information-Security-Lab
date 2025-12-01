from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import base64


def triple_des_encrypt(plaintext, key_hex):
    """
    Encrypt using Triple DES (3DES) in CBC mode
    """
    # Convert hex key to bytes
    key = bytes.fromhex(key_hex)

    # Create cipher with random IV
    cipher = DES3.new(key, DES3.MODE_CBC)

    # Pad and encrypt
    plaintext_bytes = plaintext.encode('utf-8')
    padded_data = pad(plaintext_bytes, DES3.block_size)
    ciphertext = cipher.encrypt(padded_data)

    # Return IV + ciphertext
    iv_ciphertext = cipher.iv + ciphertext
    return base64.b64encode(iv_ciphertext).decode('utf-8')


def triple_des_decrypt(ciphertext_b64, key_hex):
    """
    Decrypt Triple DES ciphertext
    """
    # Convert hex key to bytes
    key = bytes.fromhex(key_hex)

    # Decode base64
    iv_ciphertext = base64.b64decode(ciphertext_b64)

    # Extract IV (first 8 bytes) and ciphertext
    iv = iv_ciphertext[:DES3.block_size]
    ciphertext = iv_ciphertext[DES3.block_size:]

    # Create cipher and decrypt
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)

    # Remove padding
    plaintext_bytes = unpad(padded_plaintext, DES3.block_size)

    return plaintext_bytes.decode('utf-8')


# Main execution with PROPER 48-char hex key (24 bytes)
# Each 16 hex chars = 8 bytes for one DES key
key = "1234567890ABCDEF234567890ABCDEF034567890ABCDEF01"
# Count: 48 characters = 24 bytes ✓

message = "Classified Text"

print("TRIPLE DES (3DES) Encryption/Decryption")
print("=" * 50)
print(f"Key hex length: {len(key)} characters")
print(f"Key byte length: {len(key) // 2} bytes")
print(f"Message: {message}")

# Encrypt
encrypted = triple_des_encrypt(message, key)
print(f"\nEncrypted (base64):")
print(encrypted)

# Decrypt
decrypted = triple_des_decrypt(encrypted, key)
print(f"\nDecrypted: {decrypted}")
print(f"Verification: {message == decrypted}")