# Office Double Encryption System

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
    result = ""
    for char in cipher:
        if char.isalpha():
            c = ord(char) - ord('A')
            p = (a_inv * (c - b)) % 26
            result += chr(p + ord('A'))
        else:
            result += char
    return result

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
    for char in cipher:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            p = (ord(char) - ord('A') - shift) % 26
            result += chr(p + ord('A'))
            key_index += 1
        else:
            result += char
    return result

print("=== Office Secure Memo System ===")
print("Encryption: Affine -> Vigenère")
print("Decryption: Vigenère -> Affine\n")

mode = input("Encrypt (E) or Decrypt (D)? ").upper()
text = input("Enter memo text: ").upper().replace(" ", "")

if mode == 'E':
    a = int(input("Affine key a: "))
    b = int(input("Affine key b: "))
    vkey = input("Vigenère keyword: ")
    step1 = affine_encrypt(text, a, b)
    step2 = vigenere_encrypt(step1, vkey)
    print(f"\nAffine encrypted: {step1}")
    print(f"Final (Vigenère): {step2}")
else:
    vkey = input("Vigenère keyword: ")
    a = int(input("Affine key a: "))
    b = int(input("Affine key b: "))
    step1 = vigenere_decrypt(text, vkey)
    step2 = affine_decrypt(step1, a, b)
    print(f"\nVigenère decrypted: {step1}")
    print(f"Final (Affine decrypted): {step2}")