import hashlib
import json

def compute_hashes(filepath):
    hashes = {"SHA256": "", "SHA1": "", "MD5": ""}
    with open(filepath, "rb") as f:
        data = f.read()
        hashes["SHA256"] = hashlib.sha256(data).hexdigest()
        hashes["SHA1"] = hashlib.sha1(data).hexdigest()
        hashes["MD5"] = hashlib.md5(data).hexdigest()
    return hashes

# Compute and store original file hashes
original_file = "original.txt"
hashes = compute_hashes(original_file)

with open("hashes.json", "w") as f:
    json.dump(hashes, f, indent=4)

# Load and compare hashes against tampered file
tampered_file = "tampered.txt"
tampered_hashes = compute_hashes(tampered_file)

with open("hashes.json", "r") as f:
    original_hashes = json.load(f)

result = "PASS"
for algo in ["SHA256", "SHA1", "MD5"]:
    if original_hashes[algo] != tampered_hashes[algo]:
        print(f"[!] {algo} mismatch: Integrity check FAILED.")
        result = "FAIL"
    else:
        print(f"[✓] {algo} match: OK.")

print("Integrity check result:", result)
