# Lab 8 - SSE with Deterministic Encryption
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib


def encrypt_deterministic(key, data):
    """Deterministic encryption for searchable encryption"""
    # Pad to 16 bytes
    data_bytes = data.encode()
    if len(data_bytes) < 16:
        data_bytes = data_bytes.ljust(16, b'\0')
    elif len(data_bytes) > 16:
        data_bytes = data_bytes[:16]

    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data_bytes)


def create_index(documents, key):
    index = {}
    for doc_id, doc in documents.items():
        for word in doc.split():
            word_lower = word.lower()
            # Hash then encrypt deterministically
            word_hash = hashlib.sha256(word_lower.encode()).hexdigest()
            encrypted_word = encrypt_deterministic(key, word_hash)

            if encrypted_word not in index:
                index[encrypted_word] = []
            index[encrypted_word].append(doc_id)
    return index


def search(encrypted_index, query, key):
    query_lower = query.lower()
    query_hash = hashlib.sha256(query_lower.encode()).hexdigest()
    encrypted_query = encrypt_deterministic(key, query_hash)

    return encrypted_index.get(encrypted_query, [])


print("SYMMETRIC SEARCHABLE ENCRYPTION (SSE)")
print("=" * 50)

# Dataset
documents = {
    "doc1": "apple banana orange fruit basket",
    "doc2": "banana split dessert recipe",
    "doc3": "orange juice breakfast drink",
    "doc4": "apple pie baking dessert",
    "doc5": "fruit salad healthy meal",
    "doc6": "banana bread breakfast food",
    "doc7": "orange marmalade sweet spread",
    "doc8": "apple cider autumn drink",
    "doc9": "banana smoothie protein shake",
    "doc10": "fruit basket gift package"
}

print(f"Dataset: {len(documents)} documents")

# Generate key
key = get_random_bytes(16)

# Create encrypted index
encrypted_index = create_index(documents, key)

# Search
print("\nSearch Results:")
queries = ["apple", "banana", "orange", "fruit", "dessert"]
for query in queries:
    results = search(encrypted_index, query, key)
    print(f"'{query}': {len(results)} docs -> {results}")

print("\n" + "=" * 50)
print("✓ SSE search on encrypted data working")