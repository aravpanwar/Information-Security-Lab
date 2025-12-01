# Lab 3 Q2 - ECC Encryption
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

print("ECC ENCRYPTION - Secure Transactions")
print("-" * 40)

# 1. Keys
priv = ec.generate_private_key(ec.SECP256R1())
pub = priv.public_key()
print("Keys generated (secp256r1)")

# 2. Encrypt
peer_priv = ec.generate_private_key(ec.SECP256R1())
peer_pub = peer_priv.public_key()
shared = priv.exchange(ec.ECDH(), peer_pub)

key = HKDF(hashes.SHA256(), 32, None, b'ecc').derive(shared)
msg = b"Secure Transactions"
iv = os.urandom(12)
cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
enc = cipher.encryptor()
ct = enc.update(msg) + enc.finalize()
tag = enc.tag

print(f"Original: {msg.decode()}")
print(f"Ciphertext: {ct.hex()[:20]}...")
print(f"IV: {iv.hex()}")

# 3. Decrypt
shared2 = peer_priv.exchange(ec.ECDH(), pub)
key2 = HKDF(hashes.SHA256(), 32, None, b'ecc').derive(shared2)
cipher = Cipher(algorithms.AES(key2), modes.GCM(iv, tag))
dec = cipher.decryptor()
pt = dec.update(ct) + dec.finalize()

print(f"Decrypted: {pt.decode()}")
if pt == msg:
    print("Verified")