# Rabin Cryptosystem - Interactive
import random

def rabin_encrypt(m, n):
    return (m * m) % n

def rabin_decrypt(c, p, q):
    n = p * q
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)
    # Extended Euclidean for yp, yq
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
    _, yp, yq = egcd(p, q)
    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = n - r1
    r3 = (yp * p * mq - yq * q * mp) % n
    r4 = n - r3
    return [r1, r2, r3, r4]

print("=== Rabin Cryptosystem ===")
print("1. Key Generation")
print("2. Encryption")
print("3. Decryption")
choice = int(input("Enter choice (1/2/3): "))

if choice == 1:
    p = int(input("Enter prime p (p ≡ 3 mod 4): "))
    q = int(input("Enter prime q (q ≡ 3 mod 4): "))
    n = p * q
    print(f"Public key (n): {n}")
    print(f"Private key (p, q): ({p}, {q})")
elif choice == 2:
    m = int(input("Enter message (as number): "))
    n = int(input("Enter public key n: "))
    c = rabin_encrypt(m, n)
    print(f"Ciphertext: {c}")
elif choice == 3:
    c = int(input("Enter ciphertext: "))
    p = int(input("Enter private key p: "))
    q = int(input("Enter private key q: "))
    possible_msgs = rabin_decrypt(c, p, q)
    print("Possible plaintexts:", possible_msgs)
else:
    print("Invalid choice")