def beaufort_cipher(text, key, mode='encrypt'):
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
                c = (p - k) % 26
            else:
                c = (p + k) % 26

            result += chr(c + ord('A'))

    return ' '.join([result[i:i + 5] for i in range(0, len(result), 5)])

# DEMO
plaintext = input("Enter Text: ")
key = input("Enter Key: ")
print("Original:", plaintext)
print()

print("Beaufort Cipher :")
enc_beaufort = beaufort_cipher(plaintext, key, 'encrypt')
dec_beaufort = beaufort_cipher(enc_beaufort.replace(" ", ""), key, 'decrypt')
print("Encrypted:", enc_beaufort)
print("Decrypted:", dec_beaufort)
print()
