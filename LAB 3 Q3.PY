# Lab 3 Q3 - ElGamal Encryption
import random
from Crypto.Util.number import getPrime, inverse

print("ELGAMAL ENCRYPTION - Confidential Data")
print("-" * 40)

# Key generation
p = getPrime(512)  # Large prime
g = random.randint(2, p-2)  # Generator
x = random.randint(1, p-2)  # Private key
h = pow(g, x, p)  # Public key part
print(f"p={hex(p)[:20]}...")
print(f"g={g}")
print(f"h={hex(h)[:20]}...")
print(f"x={hex(x)[:20]}...")

# Encryption
msg = b"Confidential Data"
m = int.from_bytes(msg, 'big') % p
k = random.randint(1, p-2)
c1 = pow(g, k, p)
c2 = (m * pow(h, k, p)) % p
print(f"\nEncrypted:")
print(f"c1={hex(c1)[:20]}...")
print(f"c2={hex(c2)[:20]}...")

# Decryption
s = pow(c1, x, p)
s_inv = inverse(s, p)
m_dec = (c2 * s_inv) % p
dec_msg = m_dec.to_bytes((m_dec.bit_length() + 7) // 8, 'big')

print(f"\nDecrypted: {dec_msg.decode()}")
if dec_msg == msg:
    print("Verified")