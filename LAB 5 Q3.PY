# Lab 5 Q3 - Hash Performance Timing
import hashlib, time, random, string

data = [''.join(random.choices(string.ascii_letters + string.digits, k=15))
        for _ in range(80)]

print("Hash Performance (80 strings)")
print("=" * 30)

# MD5
start = time.time()
[h.encode() for h in data]  # Warmup
md5_hashes = [hashlib.md5(s.encode()).hexdigest() for s in data]
md5_time = time.time() - start

# SHA-1
start = time.time()
sha1_hashes = [hashlib.sha1(s.encode()).hexdigest() for s in data]
sha1_time = time.time() - start

# SHA-256
start = time.time()
sha256_hashes = [hashlib.sha256(s.encode()).hexdigest() for s in data]
sha256_time = time.time() - start

print(f"MD5:    {md5_time:.6f}s")
print(f"SHA-1:  {sha1_time:.6f}s")
print(f"SHA-256: {sha256_time:.6f}s")