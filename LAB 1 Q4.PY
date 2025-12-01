# Hill Cipher Implementation
def hill_cipher_encrypt(text, key_matrix):
    # Clean and prepare text
    text = text.upper().replace(" ", "")
    if len(text) % 2 != 0:
        text += 'X'  # Pad if odd length

    # Encrypt
    result = ""
    for i in range(0, len(text), 2):
        # Get letter values (A=0, B=1, ..., Z=25)
        p1 = ord(text[i]) - ord('A')
        p2 = ord(text[i + 1]) - ord('A')

        # Apply matrix multiplication
        # K = [[a, b], [c, d]]
        # C1 = (a*p1 + b*p2) mod 26
        # C2 = (c*p1 + d*p2) mod 26
        a, b, c, d = key_matrix[0][0], key_matrix[0][1], key_matrix[1][0], key_matrix[1][1]

        c1 = (a * p1 + b * p2) % 26
        c2 = (c * p1 + d * p2) % 26

        # Convert back to letters
        result += chr(c1 + ord('A'))
        result += chr(c2 + ord('A'))

    return ' '.join([result[i:i + 5] for i in range(0, len(result), 5)])


# Main program
key = [[3, 3], [2, 7]]
message = "We live in an insecure world"

print("HILL CIPHER ENCRYPTION")
print("=" * 30)
print(f"Message: {message}")
print(f"Key Matrix: [[{key[0][0]}, {key[0][1]}], [{key[1][0]}, {key[1][1]}]]")

plaintext = message.upper().replace(" ", "")
print(f"Plaintext (no spaces): {plaintext}")

ciphertext = hill_cipher_encrypt(message, key)
print(f"Ciphertext: {ciphertext}")