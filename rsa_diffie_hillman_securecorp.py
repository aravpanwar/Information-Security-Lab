# RSA + Diffie-Hellman Hybrid (Simplified)
import random

def rsa_encrypt(m, e, n):
    return pow(m, e, n)

def rsa_decrypt(c, d, n):
    return pow(c, d, n)

def diffie_hellman(p, g, private):
    return pow(g, private, p)

print("=== SecureCorp Secure Communication ===")
print("Step 1: RSA Key Exchange")
print("Step 2: Diffie-Hellman Shared Secret")

# RSA part
print("\n--- RSA ---")
p_rsa = int(input("Enter RSA prime p: "))
q_rsa = int(input("Enter RSA prime q: "))
n_rsa = p_rsa * q_rsa
phi = (p_rsa-1)*(q_rsa-1)
e_rsa = 65537
d_rsa = pow(e_rsa, -1, phi)
print(f"RSA Public Key (n, e): ({n_rsa}, {e_rsa})")
print(f"RSA Private Key d: {d_rsa}")

msg = int(input("Enter a secret number to send via RSA: "))
cipher = rsa_encrypt(msg, e_rsa, n_rsa)
print(f"Encrypted (RSA): {cipher}")
decrypted = rsa_decrypt(cipher, d_rsa, n_rsa)
print(f"Decrypted (RSA): {decrypted}")

# Diffie-Hellman part
print("\n--- Diffie-Hellman ---")
p_dh = int(input("Enter DH prime p: "))
g_dh = int(input("Enter DH generator g: "))
alice_private = random.randint(2, p_dh-2)
bob_private = random.randint(2, p_dh-2)

alice_public = diffie_hellman(p_dh, g_dh, alice_private)
bob_public = diffie_hellman(p_dh, g_dh, bob_private)

print(f"Alice's public: {alice_public}")
print(f"Bob's public: {bob_public}")

shared_alice = pow(bob_public, alice_private, p_dh)
shared_bob = pow(alice_public, bob_private, p_dh)
print(f"Shared secret (Alice): {shared_alice}")
print(f"Shared secret (Bob): {shared_bob}")
if shared_alice == shared_bob:
    print("✓ Key exchange successful!")
else:
    print("✗ Error in key exchange")