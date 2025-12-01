def create_playfair_matrix(key):
    # Create 5x5 Playfair matrix
    key = key.upper().replace("J", "I")  # I and J share same cell
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # No J

    matrix = []
    used = set()

    # Add key letters first
    for char in key + alphabet:
        if char not in used and char.isalpha():
            used.add(char)
            matrix.append(char)

    # Reshape to 5x5
    return [matrix[i:i + 5] for i in range(0, 25, 5)]


def prepare_text(text):
    # Prepare text for Playfair
    text = text.upper().replace("J", "I")
    text = ''.join([c for c in text if c.isalpha()])

    # Split into digraphs, handle double letters and odd length
    digraphs = []
    i = 0
    while i < len(text):
        if i == len(text) - 1:
            # Last character alone
            digraphs.append(text[i] + 'X')
            i += 1
        elif text[i] == text[i + 1]:
            # Double letter, insert X
            digraphs.append(text[i] + 'X')
            i += 1
        else:
            # Normal pair
            digraphs.append(text[i:i + 2])
            i += 2

    return digraphs


def find_position(matrix, char):
    # Find row and column of a character in matrix
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return None


def playfair_encrypt(plaintext, key):
    # Encrypt using Playfair cipher
    matrix = create_playfair_matrix(key)
    digraphs = prepare_text(plaintext)
    ciphertext = ""

    print("Key Matrix:")
    for row in matrix:
        print(' '.join(row))
    print(f"\nDigraphs: {digraphs}\n")

    for a, b in digraphs:
        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        if r1 == r2:
            # Same row: shift right
            ciphertext += matrix[r1][(c1 + 1) % 5]
            ciphertext += matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:
            # Same column: shift down
            ciphertext += matrix[(r1 + 1) % 5][c1]
            ciphertext += matrix[(r2 + 1) % 5][c2]
        else:
            # Rectangle: swap columns
            ciphertext += matrix[r1][c2]
            ciphertext += matrix[r2][c1]

    return ' '.join([ciphertext[i:i + 5] for i in range(0, len(ciphertext), 5)])


# DEMO
key = "GUIDANCE"
plaintext = "The key is hidden under the door pad"

print("Playfair Cipher Example")
print("=" * 40)
print(f"Key: {key}")
print(f"Plaintext: {plaintext}")
print()

ciphertext = playfair_encrypt(plaintext, key)
print(f"Ciphertext: {ciphertext}")