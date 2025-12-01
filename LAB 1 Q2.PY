def vigenere_cipher(text, key, mode='encrypt'):
    result = ""
    text = text.upper().replace(" ", "")
    key = key.upper().replace(" ", "")

    # Repeat key to match text length
    key_repeated = (key * (len(text) // len(key) + 1))[:len(text)]

    for i in range(len(text)):
        if text[i].isalpha():
            p = ord(text[i]) - ord('A')
            k = ord(key_repeated[i]) - ord('A')

            if mode == 'encrypt':
                c = (p + k) % 26
            else:
                c = (p - k) % 26

            result += chr(c + ord('A'))

    return ' '.join([result[i:i + 5] for i in range(0, len(result), 5)])


def autokey_cipher(text, initial_key, mode='encrypt'):
    result = ""
    text = text.upper().replace(" ", "")

    if mode == 'encrypt':
        # Encryption: first char uses initial_key, then use plaintext as key
        for i in range(len(text)):
            if text[i].isalpha():
                p = ord(text[i]) - ord('A')

                if i == 0:
                    k = initial_key
                else:
                    k = ord(text[i - 1]) - ord('A')  # Use previous plaintext as key

                c = (p + k) % 26
                result += chr(c + ord('A'))

    else:
        # Decryption: first char uses initial_key, then use decrypted plaintext as key
        plaintext_chars = []
        for i in range(len(text)):
            if text[i].isalpha():
                c = ord(text[i]) - ord('A')

                if i == 0:
                    p = (c - initial_key) % 26
                else:
                    p = (c - (ord(plaintext_chars[i - 1]) - ord('A'))) % 26

                plaintext_char = chr(p + ord('A'))
                plaintext_chars.append(plaintext_char)
                result += plaintext_char

    return ' '.join([result[i:i + 5] for i in range(0, len(result), 5)])


# DEMO
plaintext = "the house is being sold tonight"
print("Original:", plaintext)
print()

print("VIGENÈRE (key='dollars'):")
enc_vigenere = vigenere_cipher(plaintext, "dollars", 'encrypt')
dec_vigenere = vigenere_cipher(enc_vigenere.replace(" ", ""), "dollars", 'decrypt')
print("Encrypted:", enc_vigenere)
print("Decrypted:", dec_vigenere)
print()

print("AUTOKEY (initial_key=7):")
enc_autokey = autokey_cipher(plaintext, 7, 'encrypt')
dec_autokey = autokey_cipher(enc_autokey.replace(" ", ""), 7, 'decrypt')
print("Encrypted:", enc_autokey)
print("Decrypted:", dec_autokey)