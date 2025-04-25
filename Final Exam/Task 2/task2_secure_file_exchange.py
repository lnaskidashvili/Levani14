from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
import os

# Step 1: Generate RSA key pair for Bob
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()

with open("bob_private.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open("bob_public.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Step 2: Alice creates a plaintext message
message = b"This is a highly confidential file that Alice is sending to Bob."
with open("alice_message.txt", "wb") as f:
    f.write(message)

# Step 3: Generate AES-256 key and IV
aes_key = os.urandom(32)
iv = os.urandom(16)

# Step 4: Encrypt file using AES
padder = sym_padding.PKCS7(128).padder()
padded_data = padder.update(message) + padder.finalize()

cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded_data) + encryptor.finalize()

with open("encrypted_file.bin", "wb") as f:
    f.write(iv + ciphertext)

# Step 5: Encrypt AES key using Bob's public RSA key
encrypted_aes_key = public_key.encrypt(
    aes_key,
    asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

with open("aes_key_encrypted_task2.bin", "wb") as f:
    f.write(encrypted_aes_key)

# Step 6: Bob decrypts AES key
decrypted_aes_key = private_key.decrypt(
    encrypted_aes_key,
    asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Step 7: Bob decrypts the encrypted message
cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()
decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

unpadder = sym_padding.PKCS7(128).unpadder()
decrypted_message = unpadder.update(decrypted_padded) + unpadder.finalize()

with open("decrypted_message_task2.txt", "wb") as f:
    f.write(decrypted_message)

# Step 8: Integrity verification
original_hash = sha256(message).hexdigest()
decrypted_hash = sha256(decrypted_message).hexdigest()
result = "PASS" if original_hash == decrypted_hash else "FAIL"

print("Integrity check result:", result)
print("Original SHA-256:", original_hash)
print("Decrypted SHA-256:", decrypted_hash)
