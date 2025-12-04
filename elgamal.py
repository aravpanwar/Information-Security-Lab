import random

def elgamal_encrypt(p, g, h, m):
    k = random.randint(2, p-2)
    c1 = pow(g, k, p)
    c2 = (m * pow(h, k, p)) % p
    return c1, c2

def elgamal_decrypt(p, x, c1, c2):
    s = pow(c1, x, p)
    s_inv = pow(s, -1, p)
    m = (c2 * s_inv) % p
    return m

print("=== ElGamal Encryption ===")
p = int(input("Enter prime p: "))
g = int(input("Enter generator g: "))
choice = input("Encrypt (E) or Decrypt (D)? ").upper()

if choice == 'E':
    h = int(input("Enter recipient's public key h: "))
    m = int(input("Enter message (as number < p): "))
    c1, c2 = elgamal_encrypt(p, g, h, m)
    print(f"Ciphertext (c1, c2): ({c1}, {c2})")
elif choice == 'D':
    x = int(input("Enter your private key x: "))
    c1 = int(input("Enter c1: "))
    c2 = int(input("Enter c2: "))
    m = elgamal_decrypt(p, x, c1, c2)
    print(f"Decrypted message: {m}")
else:
    print("Invalid choice")