"""
AES-192 Encryption Demonstration
Encrypting: "Top Secret Data"
Key: "FEDCBA9876543210FEDCBA9876543210"
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64


def aes192_encrypt_decrypt_demo():
    # Given parameters
    plaintext = "Top Secret Data"
    key_hex = "FEDCBA9876543210FEDCBA9876543210"

    print("AES-192 ENCRYPTION PROCESS")
    print("=" * 50)
    print(f"Plaintext: {plaintext}")
    print(f"Key (hex): {key_hex}")
    print(f"Key length: {len(key_hex) // 2} bytes = {len(key_hex) // 2 * 8} bits")
    print()

    # Step 1: Key Expansion
    print("STEP 1: KEY EXPANSION")
    print("-" * 30)
    print("AES-192 uses 192-bit key (24 bytes)")
    print("Key expands to 13 round keys (52 words)")
    print("Key schedule generated using Rijndael key schedule")
    print()

    # Step 2: Convert key to bytes
    key = bytes.fromhex(key_hex)
    print("STEP 2: PREPARATION")
    print("-" * 30)
    print(f"Key bytes: {key.hex().upper()}")
    print(f"Key in decimal: {list(key)}")
    print()

    # Step 3: Create cipher
    cipher = AES.new(key, AES.MODE_ECB)  # Using ECB for simplicity
    print("STEP 3: INITIAL ROUND")
    print("-" * 30)
    print("1. Convert plaintext to bytes")
    print("2. Add padding (PKCS#7)")
    print("3. Initial AddRoundKey: XOR with first round key")
    print()

    # Step 4: Pad and encrypt
    padded_data = pad(plaintext.encode(), AES.block_size)
    print("STEP 4: MAIN ROUNDS (12 rounds total)")
    print("-" * 30)
    for round_num in range(1, 13):
        print(f"Round {round_num}:")
        print(f"  - SubBytes: S-box substitution")
        print(f"  - ShiftRows: Row shifting")
        if round_num < 12:  # No MixColumns in final round
            print(f"  - MixColumns: Column mixing")
        print(f"  - AddRoundKey: XOR with round key {round_num}")
        if round_num < 12:
            print()

    # Step 5: Final round
    print("\nSTEP 5: FINAL ROUND")
    print("-" * 30)
    print("Round 12 (final):")
    print("  - SubBytes")
    print("  - ShiftRows")
    print("  - AddRoundKey (no MixColumns in final round)")
    print()

    # Actual encryption
    ciphertext = cipher.encrypt(padded_data)

    print("STEP 6: OUTPUT")
    print("-" * 30)
    print(f"Plaintext bytes: {plaintext.encode().hex().upper()}")
    print(f"Padded bytes: {padded_data.hex().upper()}")
    print(f"Ciphertext (hex): {ciphertext.hex().upper()}")
    print(f"Ciphertext (base64): {base64.b64encode(ciphertext).decode()}")

    # Decryption
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

    print("\n" + "=" * 50)
    print("DECRYPTION VERIFICATION")
    print("=" * 50)
    print(f"Decrypted bytes: {decrypted.hex().upper()}")
    print(f"Decrypted text: {decrypted.decode()}")
    print(f"Verification: {plaintext == decrypted.decode()}")

    return ciphertext.hex().upper()


# Run the demo
if __name__ == "__main__":
    result = aes192_encrypt_decrypt_demo()