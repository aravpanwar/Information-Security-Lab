# College Secure Grade Transmission
import time
from tkinter.messagebox import YESNO

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64, random
p = 131
g = 7
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

def rsa_encrypt_simple(m, e, n):
    return pow(m, e, n)

def rsa_decrypt_simple(c, d, n):
    return pow(c, d, n)

start = time.time()
print("Start time: ")
print(start)

print("----Secure Payment Processing----")
print("Select \n1 for Customer. \n2 for Merchant. \n3 for Auditor.")
choice = input("Enter Choice: ")
if choice == "1":
    print("Customer: \n")
elif choice == "2":
    print("Merchant: \n")
elif choice == "3":
    print("Auditor: \n")

# RSA keys (simple numbers for demo)
n = 3233  # public key n
e = 17    # public exponent
d = 2753  # private exponent
print("Customer: \n")

# Generate random AES key
aes_key = get_random_bytes(16)
print(f"AES Key: {aes_key.hex()}")
print("AES Time:")
time1 = time.time() - start
print(time1)

# Encrypt AES key with RSA
aes_key_int = int.from_bytes(aes_key, byteorder='big')
encrypted_key = rsa_encrypt_simple(aes_key_int, e, n)
print(f"Encrypted AES key (RSA): {encrypted_key}")


# AES encryption
message = input("\nEnter payment information (e.g., 'John Doe: A, Math: B+'): ")
cipher_aes = AES.new(aes_key, AES.MODE_CBC)
iv = cipher_aes.iv
encrypted_msg = cipher_aes.encrypt(pad(message.encode(), AES.block_size))
print(f"IV: {iv.hex()}")
print(f"Encrypted message: {base64.b64encode(encrypted_msg).decode()}")
time2 = time.time() - start
print("Encrypted Time: ")
print(time2)
confirm1 = input("Enter 1 to Confirm: ")
if confirm1 == "1":
    print("Confirmed \n")
else:
    print("Failed \n")
    input("Press enter to exit.")
    exit()
print("Confirm Time: ")
time3 = time.time() - start
print(time3)
print("\n")
choice1 = input("Encrypt (E) or Decrypt (D)? ").upper()

if choice1 == 'E':
    h = int(input("Enter recipient's public key h: "))
    m = int(input("Enter message (as number < p): "))
    c1, c2 = elgamal_encrypt(p, g, h, m)
    print(f"Ciphertext (c1, c2): ({c1}, {c2})")
elif 1 == 'D':
    x = int(input("Enter your private key x: "))
    c1 = int(input("Enter c1: "))
    c2 = int(input("Enter c2: "))
    m = elgamal_decrypt(p, x, c1, c2)
    print(f"Decrypted message: {m}")
else:
    print("Invalid choice")

# Decryption demo
print("\n--- Merchant ---")
decrypted_key_int = rsa_decrypt_simple(encrypted_key, d, n)
decrypted_aes_key = decrypted_key_int.to_bytes(16, byteorder='big')
cipher_aes_dec = AES.new(decrypted_aes_key, AES.MODE_CBC, iv)
decrypted_msg = unpad(cipher_aes_dec.decrypt(encrypted_msg), AES.block_size)
print(f"Decrypted message: {decrypted_msg.decode()}")



