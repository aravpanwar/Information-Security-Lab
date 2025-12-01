# Lab 6 - ElGamal Digital Signatures (Fixed)
import random
from Crypto.Util.number import getPrime, inverse, GCD


def elgamal_keygen(bits=256):
    """Generate ElGamal keys"""
    p = getPrime(bits)
    g = random.randint(2, p - 2)
    x = random.randint(1, p - 2)
    y = pow(g, x, p)
    return (p, g, y), x


def elgamal_sign(message, private_key, p, g):
    """Sign a message"""
    x = private_key
    m = hash(message) % (p - 1)  # Hash message to number

    # Find k coprime with p-1
    while True:
        k = random.randint(1, p - 2)
        if GCD(k, p - 1) == 1:
            break

    r = pow(g, k, p)
    kinv = inverse(k, p - 1)
    s = ((m - x * r) * kinv) % (p - 1)
    return (r, s)


def elgamal_verify(message, signature, public_key):
    """Verify a signature"""
    p, g, y = public_key
    r, s = signature
    m = hash(message) % (p - 1)

    if not (0 < r < p and 0 < s < p - 1):
        return False

    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, m, p)
    return v1 == v2


print("ELGAMAL DIGITAL SIGNATURES")
print("=" * 40)

# Step 1: Generate keys
print("1. Key Generation:")
pub, priv = elgamal_keygen(128)
print(f"   Public (p,g,y):")
print(f"   p = {pub[0]}")
print(f"   g = {pub[1]}")
print(f"   y = {pub[2]}")
print(f"   Private x = {priv}")

# Step 2: Sign document
print("\n2. Sign document 'Legal Agreement':")
sig = elgamal_sign("Legal Agreement", priv, pub[0], pub[1])
print(f"   Signature (r,s):")
print(f"   r = {sig[0]}")
print(f"   s = {sig[1]}")

# Step 3: Verify
print("\n3. Verify signature:")
valid = elgamal_verify("Legal Agreement", sig, pub)
print(f"   Valid: {valid}")

# Step 4: Test tampering
print("\n4. Test tampering detection:")
tampered = elgamal_verify("Modified Agreement", sig, pub)
print(f"   Tampered valid: {tampered}")
print(f"   Detection: {not tampered}")

print("\n" + "=" * 40)
print("ElGamal signatures working")