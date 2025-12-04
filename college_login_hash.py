# College Login System with Hashing
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Simulated database
users_db = {
    "student1": hash_password("hello123"),
    "admin": hash_password("secure@2025")
}

print("=== College Login System ===")
username = input("Username: ")
password = input("Password: ")

hashed_input = hash_password(password)

if username in users_db and users_db[username] == hashed_input:
    print("✅ Login successful!")
    # Simulate sending a secure token
    token = hashlib.sha256((username + password).encode()).hexdigest()
    print(f"Your session token: {token[:16]}...")
else:
    print("❌ Login failed.")