# Lab 7 Q2 - RSA Multiplicative Homomorphism
from Crypto.Util.number import getPrime, inverse, GCD


class RSAHomomorphic:
    def __init__(self, bits=128):
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        self.n = p * q
        phi = (p - 1) * (q - 1)
        self.e = 65537
        self.d = inverse(self.e, phi)

    def encrypt(self, m):
        return pow(m, self.e, self.n)

    def decrypt(self, c):
        return pow(c, self.d, self.n)

    def homomorphic_multiply(self, c1, c2):
        return (c1 * c2) % self.n


print("RSA MULTIPLICATIVE HOMOMORPHISM")
print("=" * 40)

# Initialize
rsa = RSAHomomorphic(128)
print(f"Public key (n,e): ({rsa.n}, {rsa.e})")

# Encrypt two integers
a = 7
b = 3
ct_a = rsa.encrypt(a)
ct_b = rsa.encrypt(b)
print(f"\nEncryption:")
print(f"Plaintext a = {a}")
print(f"Ciphertext a = {ct_a}")
print(f"\nPlaintext b = {b}")
print(f"Ciphertext b = {ct_b}")

# Homomorphic multiplication
ct_product = rsa.homomorphic_multiply(ct_a, ct_b)
print(f"\nHomomorphic Multiplication:")
print(f"Ciphertext of a*b = {ct_product}")

# Decrypt result
decrypted = rsa.decrypt(ct_product)
print(f"\nDecryption:")
print(f"Decrypted product = {decrypted}")
print(f"Expected product = {a * b}")
print(f"Match: {decrypted == a * b}")

print("\n" + "=" * 40)
print("Multiplicative homomorphism verified")