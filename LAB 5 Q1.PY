# Lab 5 Q1 - Custom Hash Function
def custom_hash(input_string):
    hash_value = 5381  # Initial value
    for char in input_string:
        # Multiply by 33, add ASCII value
        hash_value = (hash_value * 33) + ord(char)
        # Bitwise mixing
        hash_value = (hash_value ^ (hash_value >> 16)) & 0xFFFFFFFF
    return hash_value

print("Custom Hash Function - Lab 5")
print("=" * 40)

# Test cases
test_strings = [
    "Hello",
    "Information Security",
    "Lab 5",
    "A" * 10,
    ""
]

for s in test_strings:
    h = custom_hash(s)
    print(f"'{s}'")
    print(f"  Hash: {h} (decimal)")
    print(f"        {hex(h)} (hex)")
    print()