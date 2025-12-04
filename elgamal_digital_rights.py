# ElGamal DRM System
import random

def elgamal_keygen(p, g):
    x = random.randint(2, p-2)
    h = pow(g, x, p)
    return (p, g, h), x

def elgamal_encrypt(pub_key, m):
    p, g, h = pub_key
    k = random.randint(2, p-2)
    c1 = pow(g, k, p)
    c2 = (m * pow(h, k, p)) % p
    return c1, c2

def elgamal_decrypt(p, x, c1, c2):
    s = pow(c1, x, p)
    s_inv = pow(s, -1, p)
    return (c2 * s_inv) % p

print("=== ElGamal DRM System ===")
print("1. Generate Master Key Pair")
print("2. Encrypt Content")
print("3. Decrypt Content")
choice = int(input("Enter choice (1/2/3): "))

if choice == 1:
    p = int(input("Enter large prime p: "))
    g = int(input("Enter generator g: "))
    pub_key, priv_key = elgamal_keygen(p, g)
    print(f"Public Key (p, g, h): {pub_key}")
    print(f"Private Key x: {priv_key}")
elif choice == 2:
    p = int(input("Enter p: "))
    g = int(input("Enter g: "))
    h = int(input("Enter h: "))
    pub_key = (p, g, h)
    m = int(input("Enter content (as number): "))
    c1, c2 = elgamal_encrypt(pub_key, m)
    print(f"Encrypted Content (c1, c2): ({c1}, {c2})")
elif choice == 3:
    c1 = int(input("Enter c1: "))
    c2 = int(input("Enter c2: "))
    p = int(input("Enter p: "))
    x = int(input("Enter private key x: "))
    m = elgamal_decrypt(p, x, c1, c2)
    print(f"Decrypted content: {m}")
else:
    print("Invalid choice")