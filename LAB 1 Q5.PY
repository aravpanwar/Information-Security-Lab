# Known plaintext attack on shift cipher
def decrypt_shift(ciphertext, key):
    plain = ""
    for c in ciphertext.upper():
        if c.isalpha():
            c_num = ord(c) - ord('A')
            p_num = (c_num - key) % 26
            plain += chr(p_num + ord('A'))
    return plain

# Find key from known pair
known_cipher = "CIW"
known_plain = "YES"

# Calculate key from first character
key = (ord(known_cipher[0]) - ord(known_plain[0])) % 26
print(f"Found key: {key}")

# Decrypt the message
tablet = "XVIEWYWI"
plaintext = decrypt_shift(tablet, key)
print(f"Tablet says: {plaintext}")