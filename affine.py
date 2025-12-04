def affine_encrypt(text, a, b):
    result = ""
    for char in text.upper():
        if char.isalpha():
            p = ord(char) - ord('A')
            c = (a * p + b) % 26
            result += chr(c + ord('A'))
        else:
            result += char
    return result

def affine_decrypt(cipher, a, b):
    a_inv = None
    for i in range(26):
        if (a * i) % 26 == 1:
            a_inv = i
            break
    if a_inv is None:
        return "No inverse for a"
    result = ""
    for char in cipher.upper():
        if char.isalpha():
            c = ord(char) - ord('A')
            p = (a_inv * (c - b)) % 26
            result += chr(p + ord('A'))
        else:
            result += char
    return result

# Main program
print("=== Affine Cipher ===")
choice = input("Encrypt (E) or Decrypt (D)? ").upper()
text = input("Enter text: ").upper().replace(" ", "")
a = int(input("Enter key 'a' (must have inverse mod 26): "))
b = int(input("Enter key 'b': "))

if choice == 'E':
    print("Encrypted:", affine_encrypt(text, a, b))
elif choice == 'D':
    print("Decrypted:", affine_decrypt(text, a, b))
else:
    print("Invalid choice")