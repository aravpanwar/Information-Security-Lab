# Lab 7 Q1 - Paillier Homomorphic Encryption
import random
from Crypto.Util.number import getPrime, GCD, inverse


class Paillier:
    def __init__(self, bits=128):
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        self.n = p * q
        self.n2 = self.n * self.n
        self.g = self.n + 1
        self.lambda_n = (p - 1) * (q - 1)
        self.mu = inverse(self.lambda_n, self.n)

    def encrypt(self, m):
        r = random.randint(1, self.n - 1)
        while GCD(r, self.n) != 1:
            r = random.randint(1, self.n - 1)
        c = (pow(self.g, m, self.n2) * pow(r, self.n, self.n2)) % self.n2
        return c

    def decrypt(self, c):
        x = pow(c, self.lambda_n, self.n2)
        l = (x - 1) // self.n
        m = (l * self.mu) % self.n
        return m

    def homomorphic_add(self, c1, c2):
        return (c1 * c2) % self.n2


print("PAILLIER HOMOMORPHIC ENCRYPTION")
print("=" * 40)

# Initialize
paillier = Paillier(128)
print(f"Public key n: {paillier.n}")

# Encrypt two integers
a = 15
b = 25
ct_a = paillier.encrypt(a)
ct_b = paillier.encrypt(b)
print(f"\nEncryption:")
print(f"Plaintext a = {a}")
print(f"Ciphertext a = {ct_a}")
print(f"\nPlaintext b = {b}")
print(f"Ciphertext b = {ct_b}")

# Homomorphic addition
ct_sum = paillier.homomorphic_add(ct_a, ct_b)
print(f"\nHomomorphic Addition:")
print(f"Ciphertext of a+b = {ct_sum}")

# Decrypt result
decrypted = paillier.decrypt(ct_sum)
print(f"\nDecryption:")
print(f"Decrypted sum = {decrypted}")
print(f"Expected sum = {a + b}")
print(f"Match: {decrypted == a + b}")

print("\n" + "=" * 40)
print("Additive homomorphism verified")