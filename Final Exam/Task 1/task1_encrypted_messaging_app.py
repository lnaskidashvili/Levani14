from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os

# Step 1: Generate RSA Key Pair for User A
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

# Save keys in PEM format
with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open("public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Step 2: User B encrypts a message using AES
message = b"This is a top secret message from User B to User A."

# Save original message
with open("message.txt", "wb") as f:
    f.write(message)

# Generate AES-256 key and IV
aes_key = os.urandom(32)
iv = os.urandom(16)

# Apply PKCS7 padding
padder = sym_padding.PKCS7(128).padder()
padded_message = padder.update(message) + padder.finalize()

# Encrypt message using AES-CBC
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded_message) + encryptor.finalize()

# Save encrypted message (IV + ciphertext)
with open("encrypted_message.bin", "wb") as f:
    f.write(iv + ciphertext)

# Step 3: Encrypt AES key using RSA public key
encrypted_aes_key = public_key.encrypt(
    aes_key,
    asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

with open("aes_key_encrypted.bin", "wb") as f:
    f.write(encrypted_aes_key)

# Step 4: User A decrypts the AES key
decrypted_aes_key = private_key.decrypt(
    encrypted_aes_key,
    asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Decrypt message
cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()
decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

# Remove padding
unpadder = sym_padding.PKCS7(128).unpadder()
plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()

# Save decrypted message
with open("decrypted_message.txt", "wb") as f:
    f.write(plaintext)

print("Task 1 completed successfully. Encrypted and decrypted files generated.")
