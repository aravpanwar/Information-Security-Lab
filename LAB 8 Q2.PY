# Lab 8 Q2 - Public Key Searchable Encryption (PKSE) with Paillier
import random
from Crypto.Util.number import getPrime, GCD, inverse
import hashlib


class PaillierPKSE:
    def __init__(self, bits=128):
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        self.n = p * q
        self.n2 = self.n * self.n
        self.g = self.n + 1
        self.lambda_n = (p - 1) * (q - 1)
        self.mu = inverse(self.lambda_n, self.n)

    def encrypt(self, m):
        """Encrypt integer m"""
        r = random.randint(1, self.n - 1)
        while GCD(r, self.n) != 1:
            r = random.randint(1, self.n - 1)
        return (pow(self.g, m, self.n2) * pow(r, self.n, self.n2)) % self.n2

    def decrypt(self, c):
        """Decrypt to integer"""
        x = pow(c, self.lambda_n, self.n2)
        l = (x - 1) // self.n
        return (l * self.mu) % self.n

    def word_to_int(self, word):
        """Convert word to integer for encryption"""
        return int.from_bytes(hashlib.sha256(word.encode()).digest()[:8], 'big') % self.n

    def create_index(self, documents):
        """Create encrypted index"""
        index = {}
        # Build plain index
        for doc_id, doc in documents.items():
            doc_num = self.word_to_int(doc_id)
            for word in doc.split():
                word_num = self.word_to_int(word.lower())
                if word_num not in index:
                    index[word_num] = []
                index[word_num].append(doc_num)

        # Encrypt index
        encrypted_index = {}
        for word_num, doc_nums in index.items():
            encrypted_word = self.encrypt(word_num)
            encrypted_docs = [self.encrypt(doc) for doc in doc_nums]
            encrypted_index[encrypted_word] = encrypted_docs

        return encrypted_index

    def search(self, encrypted_index, query, paillier_obj):
        """Search encrypted index"""
        query_num = self.word_to_int(query.lower())
        encrypted_query = self.encrypt(query_num)

        # Find matching encrypted word
        for enc_word, enc_docs in encrypted_index.items():
            # Compare by decrypting (in real PKSE, would use homomorphic properties)
            if self.decrypt(enc_word) == query_num:
                # Decrypt document IDs
                return [self.decrypt(enc_doc) for enc_doc in enc_docs]
        return []


print("PUBLIC KEY SEARCHABLE ENCRYPTION (PKSE)")
print("=" * 50)

# 2a. Create dataset
documents = {
    "report1": "financial analysis quarterly earnings",
    "report2": "market research consumer trends",
    "report3": "budget planning fiscal year",
    "report4": "investment portfolio management",
    "report5": "revenue growth projections",
    "report6": "cost analysis expenditure report",
    "report7": "profit margin improvement",
    "report8": "economic indicators forecast",
    "report9": "financial statements audit",
    "report10": "capital investment strategy"
}

print(f"Dataset: {len(documents)} documents")
print(f"Sample: 'report1': {documents['report1']}")

# 2b. Initialize Paillier
paillier = PaillierPKSE(128)
print(f"\nPaillier public key n: {paillier.n}")

# 2c. Create encrypted index
encrypted_index = paillier.create_index(documents)
print(f"Encrypted index size: {len(encrypted_index)} words")

# 2d. Search
print("\nSearch Results:")
queries = ["financial", "analysis", "report", "investment", "growth"]
for query in queries:
    results = paillier.search(encrypted_index, query, paillier)
    # Convert numeric results back to doc IDs
    doc_results = []
    for res in results:
        for doc_id, doc in documents.items():
            if paillier.word_to_int(doc_id) == res:
                doc_results.append(doc_id)
                break
    print(f"'{query}': {len(doc_results)} docs -> {doc_results}")

print("\n" + "=" * 50)
print("PKSE with Paillier implemented")
print("Note: This is a simplified demo - real PKSE uses homomorphic properties")