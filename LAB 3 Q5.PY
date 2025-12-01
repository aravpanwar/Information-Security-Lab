# Lab 3 Q5 - Diffie-Hellman Key Exchange
import random, time

print("Diffie-Hellman Key Exchange")
print("=" * 30)

# Public parameters (agreed beforehand)
p = 23  # Small prime for demo
g = 5   # Generator

# Alice
start = time.time()
a_private = random.randint(1, p-1)
a_public = pow(g, a_private, p)
alice_time = time.time() - start

# Bob
start = time.time()
b_private = random.randint(1, p-1)
b_public = pow(g, b_private, p)
bob_time = time.time() - start

# Exchange public keys and compute shared secret
shared_a = pow(b_public, a_private, p)
shared_b = pow(a_public, b_private, p)

print(f"Prime (p): {p}")
print(f"Base (g): {g}")
print(f"\nAlice private: {a_private}")
print(f"Alice public: {a_public}")
print(f"Bob private: {b_private}")
print(f"Bob public: {b_public}")
print(f"\nShared secret (Alice): {shared_a}")
print(f"Shared secret (Bob): {shared_b}")
print(f"\nKey gen time - Alice: {alice_time:.4f}s")
print(f"Key gen time - Bob: {bob_time:.4f}s")
print(f"Match: {shared_a == shared_b}")