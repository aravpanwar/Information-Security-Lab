# Lab 3 - Task 1: RSA Encryption & Decryption
# Encrypt "Asymmetric Encryption" with public key, decrypt with private key

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

print("=" * 60)
print("RSA ENCRYPTION & DECRYPTION - LAB 3")
print("=" * 60)

# ---------- 1. Generate RSA Keys ----------
key = RSA.generate(2048)  # 2048-bit RSA
private_key = key
public_key = key.publickey()

print("[1] RSA Key Pair Generated")
print(f"    n (modulus): {key.n}")
print(f"    e (public exponent): {key.e}")
print(f"    d (private exponent): {key.d}\n")

# ---------- 2. Encrypt with Public Key ----------
message = b"Asymmetric Encryption"
cipher_rsa = PKCS1_OAEP.new(public_key)
encrypted_msg = cipher_rsa.encrypt(message)

print("[2] Encryption using Public Key (n, e)")
print(f"    Original Message: {message.decode()}")
print(f"    Encrypted (hex): {encrypted_msg.hex()}")
print(f"    Encrypted (base64): {base64.b64encode(encrypted_msg).decode()}\n")

# ---------- 3. Decrypt with Private Key ----------
decipher_rsa = PKCS1_OAEP.new(private_key)
decrypted_msg = decipher_rsa.decrypt(encrypted_msg)

print("[3] Decryption using Private Key (n, d)")
print(f"    Decrypted Message: {decrypted_msg.decode()}")

# ---------- 4. Verification ----------
if decrypted_msg == message:
    print("\n[✓] VERIFICATION PASSED: Original == Decrypted")
else:
    print("\n[✗] VERIFICATION FAILED")

print("\n" + "=" * 60)