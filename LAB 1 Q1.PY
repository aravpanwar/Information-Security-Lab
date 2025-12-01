def additive_cipher(text, key, mode='encrypt'):
    result = ""
    text = text.upper().replace(" ", "")
    for char in text:
        if char.isalpha():
            p = ord(char) - ord('A')
            c = (p + key) % 26 if mode == 'encrypt' else (p - key) % 26
            result += chr(c + ord('A'))
    return ' '.join([result[i:i + 5] for i in range(0, len(result), 5)])


def multiplicative_cipher(text, key, mode='encrypt'):
    def mod_inverse(a, m):
        for i in range(1, m):
            if (a * i) % m == 1: return i
        return None

    result = ""
    text = text.upper().replace(" ", "")

    if mode == 'decrypt':
        key = mod_inverse(key, 26)
        if key is None: return "Invalid key - no modular inverse"

    for char in text:
        if char.isalpha():
            p = ord(char) - ord('A')
            result += chr((p * key) % 26 + ord('A'))
    return ' '.join([result[i:i + 5] for i in range(0, len(result), 5)])


def affine_cipher(text, key_a, key_b, mode='encrypt'):
    def mod_inverse(a, m):
        for i in range(1, m):
            if (a * i) % m == 1: return i
        return None

    result = ""
    text = text.upper().replace(" ", "")

    for char in text:
        if char.isalpha():
            p = ord(char) - ord('A')
            if mode == 'encrypt':
                c = (key_a * p + key_b) % 26
            else:
                a_inv = mod_inverse(key_a, 26)
                if a_inv is None: return "Invalid key A"
                c = (a_inv * (p - key_b)) % 26
            result += chr(c + ord('A'))
    return ' '.join([result[i:i + 5] for i in range(0, len(result), 5)])


# DEMO
plaintext = "I am learning information security"
print("Original:", plaintext)
print()

print("ADDITIVE (key=20):")
enc = additive_cipher(plaintext, 20, 'encrypt')
dec = additive_cipher(enc.replace(" ", ""), 20, 'decrypt')
print("Encrypted:", enc)
print("Decrypted:", dec)
print()

print("MULTIPLICATIVE (key=15):")
enc = multiplicative_cipher(plaintext, 15, 'encrypt')
dec = multiplicative_cipher(enc.replace(" ", ""), 15, 'decrypt')
print("Encrypted:", enc)
print("Decrypted:", dec)
print()

print("AFFINE (keys=15,20):")
enc = affine_cipher(plaintext, 15, 20, 'encrypt')
dec = affine_cipher(enc.replace(" ", ""), 15, 20, 'decrypt')
print("Encrypted:", enc)
print("Decrypted:", dec)