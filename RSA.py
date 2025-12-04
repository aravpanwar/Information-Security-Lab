def rsa_encrypt(m, e, n):
    return pow(m, e, n)

def rsa_decrypt(c, d, n):
    return pow(c, d, n)

print("=== RSA Encryption/Decryption ===")
print("Assume p, q are already chosen and n, e, d are known.")
print("Enter numbers for encryption/decryption.")

choice = input("Encrypt (E) or Decrypt (D)? ").upper()

if choice == 'E':
    m = int(input("Enter message (as number): "))
    e = int(input("Enter public exponent e: "))
    n = int(input("Enter modulus n: "))
    c = rsa_encrypt(m, e, n)
    print(f"Ciphertext: {c}")
elif choice == 'D':
    c = int(input("Enter ciphertext (as number): "))
    d = int(input("Enter private exponent d: "))
    n = int(input("Enter modulus n: "))
    m = rsa_decrypt(c, d, n)
    print(f"Plaintext: {m}")
else:
    print("Invalid choice")