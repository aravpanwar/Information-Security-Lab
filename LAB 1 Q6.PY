cipher = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"

a, b = 5, 6
inv = 21

plain = ""
for c in cipher:
    c_num = ord(c) - ord('A')
    p_num = (inv * (c_num - b)) % 26
    plain += chr(p_num + ord('A'))

print(f"Key: a={a}, b={b}")
print(f"Plaintext: {plain}")