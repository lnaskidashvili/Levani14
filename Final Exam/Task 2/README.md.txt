Steps Performed
1.	1. Bob generates RSA key pair (private.pem and public.pem).
2.	2. Alice creates a plaintext file called alice_message.txt.
3.	3. Alice generates a random AES-256 key and a 16-byte IV.
4.	4. The file is encrypted using AES-256 in CBC mode.
5.	5. AES key is encrypted with Bob’s RSA public key.
6.	6. Bob decrypts the AES key using his private RSA key.
7.	7. Bob decrypts the message using the AES key and IV.
8.	8. SHA-256 hash of the original and decrypted file is compared for integrity.
Ubuntu-Compatible Commands
To run the Python script, ensure you have Python 3 and cryptography library installed:

python3 _script_name.py
Generated Files
•	alice_message.txt – Original plaintext file from Alice.
•	encrypted_file.bin – AES-encrypted content.
•	aes_key_encrypted_task2.bin – AES key encrypted with RSA.
•	decrypted_message_task2.txt – Decrypted file by Bob.
•	bob_private.pem and bob_public.pem – RSA key pair for Bob.
Integrity Verification
SHA-256 Hash of Original: f665cc7a08b6201fa55b99ca6040c44ccb48fc1de0c95084b8015429ccf599e9
SHA-256 Hash of Decrypted: f665cc7a08b6201fa55b99ca6040c44ccb48fc1de0c95084b8015429ccf599e9
Integrity Check Result: PASS
AES vs RSA Comparison
AES (Advanced Encryption Standard):
- Symmetric key algorithm (same key for encryption/decryption).
- Very fast, suitable for encrypting large data files.
- Commonly used in data at rest (e.g., file storage).
RSA (Rivest–Shamir–Adleman):
- Asymmetric key algorithm (public/private key pair).
- Slower, used for secure key exchange.
- Often used to encrypt symmetric keys 