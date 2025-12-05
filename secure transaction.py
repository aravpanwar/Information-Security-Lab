import random
from sympy import nextprime
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes


# ----------------- RSA Functions -----------------
def rsa_keygen(bits=256):
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return (e, n), (d, n)


def rsa_encrypt(pub_key, msg):
    e, n = pub_key
    m = bytes_to_long(msg.encode())
    c = pow(m, e, n)
    return c


def rsa_decrypt(priv_key, c):
    d, n = priv_key
    m = pow(c, d, n)
    return long_to_bytes(m).decode()


# ----------------- ElGamal Functions -----------------
def elgamal_keygen(bits=256):
    p = getPrime(bits)
    g = random.randint(2, p - 2)
    x = random.randint(1, p - 2)
    h = pow(g, x, p)
    return (p, g, h), x


def elgamal_encrypt(pub_key, msg):
    p, g, h = pub_key
    m = bytes_to_long(msg.encode())
    y = random.randint(1, p - 2)
    c1 = pow(g, y, p)
    s = pow(h, y, p)
    c2 = (m * s) % p
    return (c1, c2)


def elgamal_decrypt(priv_key, pub_key, cipher):
    p, g, h = pub_key
    x = priv_key
    c1, c2 = cipher
    s = pow(c1, x, p)
    m = (c2 * pow(s, -1, p)) % p
    return long_to_bytes(m).decode()


# ----------------- Main Menu -----------------
def main():
    print("\n🔐 Secure Transaction System (RSA + ElGamal)")
    print("1. Customer (Encrypt Transaction)")
    print("2. Merchant (Decrypt Transaction)")
    print("3. Auditor (View Result)")
    print("4. Exit")

    # Generate keys once
    rsa_pub, rsa_priv = rsa_keygen()
    elg_pub, elg_priv = elgamal_keygen()

    encrypted_rsa = None
    encrypted_elg = None
    decrypted_msg = None

    while True:
        choice = input("\nSelect role (1-4): ")

        if choice == '1':
            # Customer
            msg = input("Enter transaction message: ")
            method = input("Encrypt with (R)SA or (E)lGamal? ").strip().upper()
            if method == 'R':
                encrypted_rsa = rsa_encrypt(rsa_pub, msg)
                print(f"✅ RSA Encrypted: {encrypted_rsa}")
            elif method == 'E':
                encrypted_elg = elgamal_encrypt(elg_pub, msg)
                print(f"✅ ElGamal Encrypted: {encrypted_elg}")
            else:
                print("❌ Invalid choice.")

        elif choice == '2':
            # Merchant
            if encrypted_rsa:
                decrypted_msg = rsa_decrypt(rsa_priv, encrypted_rsa)
                print(f"🔓 Decrypted (RSA): {decrypted_msg}")
            elif encrypted_elg:
                decrypted_msg = elgamal_decrypt(elg_priv, elg_pub, encrypted_elg)
                print(f"🔓 Decrypted (ElGamal): {decrypted_msg}")
            else:
                print("❌ No encrypted message available.")

        elif choice == '3':
            # Auditor (read-only)
            if decrypted_msg:
                print(f"📄 Auditor View: Transaction = '{decrypted_msg}'")
            else:
                print("📄 Auditor View: No transaction finalized yet.")

        elif choice == '4':
            print("👋 Exiting...")
            break
        else:
            print("❌ Invalid option.")


if __name__ == "__main__":
    main()