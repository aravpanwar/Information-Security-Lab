# Library E-book Encryption System
import random

def elgamal_encrypt(p, g, h, m):
    k = random.randint(2, p-2)
    c1 = pow(g, k, p)
    c2 = (m * pow(h, k, p)) % p
    return c1, c2

def elgamal_decrypt(p, x, c1, c2):
    s = pow(c1, x, p)
    s_inv = pow(s, -1, p)
    return (c2 * s_inv) % p

print("=== Library E-book Encryption ===")
print("1. Generate Member Key")
print("2. Encrypt Book (as number)")
print("3. Decrypt Book")
choice = int(input("Enter choice (1/2/3): "))

if choice == 1:
    p = int(input("Enter prime p: "))
    g = int(input("Enter generator g: "))
    x = random.randint(2, p-2)
    h = pow(g, x, p)
    print(f"\nMember Public Key (p, g, h): ({p}, {g}, {h})")
    print(f"Member Private Key x: {x} (keep secret!)")
elif choice == 2:
    p = int(input("Enter p: "))
    g = int(input("Enter g: "))
    h = int(input("Enter recipient's h: "))
    m = int(input("Enter book ID (as number): "))
    c1, c2 = elgamal_encrypt(p, g, h, m)
    print(f"\nEncrypted Book (c1, c2): ({c1}, {c2})")
elif choice == 3:
    p = int(input("Enter p: "))
    x = int(input("Enter your private key x: "))
    c1 = int(input("Enter c1: "))
    c2 = int(input("Enter c2: "))
    m = elgamal_decrypt(p, x, c1, c2)
    print(f"\nDecrypted Book ID: {m}")
else:
    print("Invalid choice")