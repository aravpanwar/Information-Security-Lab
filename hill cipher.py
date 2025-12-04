import numpy as np

def mod_inv_det(det):
    for i in range(26):
        if (det * i) % 26 == 1:
            return i
    return None

def hill_encrypt(text, key_matrix):
    text = text.upper().replace(" ", "")
    if len(text) % 2 != 0:
        text += 'X'
    result = ""
    for i in range(0, len(text), 2):
        p1 = ord(text[i]) - ord('A')
        p2 = ord(text[i+1]) - ord('A')
        c1 = (key_matrix[0][0]*p1 + key_matrix[0][1]*p2) % 26
        c2 = (key_matrix[1][0]*p1 + key_matrix[1][1]*p2) % 26
        result += chr(c1 + ord('A')) + chr(c2 + ord('A'))
    return result

def hill_decrypt(cipher, key_matrix):
    det = (key_matrix[0][0]*key_matrix[1][1] - key_matrix[0][1]*key_matrix[1][0]) % 26
    det_inv = mod_inv_det(det)
    if det_inv is None:
        return "No inverse"
    inv = [[0,0],[0,0]]
    inv[0][0] = (key_matrix[1][1] * det_inv) % 26
    inv[0][1] = (-key_matrix[0][1] * det_inv) % 26
    inv[1][0] = (-key_matrix[1][0] * det_inv) % 26
    inv[1][1] = (key_matrix[0][0] * det_inv) % 26
    result = ""
    for i in range(0, len(cipher), 2):
        c1 = ord(cipher[i]) - ord('A')
        c2 = ord(cipher[i+1]) - ord('A')
        p1 = (inv[0][0]*c1 + inv[0][1]*c2) % 26
        p2 = (inv[1][0]*c1 + inv[1][1]*c2) % 26
        result += chr(p1 + ord('A')) + chr(p2 + ord('A'))
    return result

print("=== Hill Cipher (2x2) ===")
key = []
print("Enter key matrix row-wise (4 integers):")
for i in range(2):
    row = list(map(int, input(f"Row {i+1}: ").split()))
    key.append(row)
choice = input("Encrypt (E) or Decrypt (D)? ").upper()
text = input("Enter text (letters only, no spaces): ").upper()

if choice == 'E':
    print("Encrypted:", hill_encrypt(text, key))
elif choice == 'D':
    print("Decrypted:", hill_decrypt(text, key))
else:
    print("Invalid choice")