def vigenere_encrypt(text, key):
    result = ""
    key = key.upper()
    key_index = 0
    for char in text.upper():
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            c = (ord(char) - ord('A') + shift) % 26
            result += chr(c + ord('A'))
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(cipher, key):
    result = ""
    key = key.upper()
    key_index = 0
    for char in cipher.upper():
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            p = (ord(char) - ord('A') - shift) % 26
            result += chr(p + ord('A'))
            key_index += 1
        else:
            result += char
    return result

print("=== Vigenère Cipher ===")
choice = input("Encrypt (E) or Decrypt (D)? ").upper()
text = input("Enter text: ")
key = input("Enter keyword: ")

if choice == 'E':
    print("Encrypted:", vigenere_encrypt(text, key))
elif choice == 'D':
    print("Decrypted:", vigenere_decrypt(text, key))
else:
    print("Invalid choice")