from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import json
import base64

############################################
#   AES Encryption
############################################

path_file = "plaintext.txt"

with open(path_file, "r") as f:
    data = f.read()

print(data)

bytes_data = data.encode("utf-8")

# Generate aes key 256-GCM and IV
aes_key = get_random_bytes(32)
iv = get_random_bytes(12)

# Encrypt text
cipher = AES.new(aes_key, AES.MODE_GCM, iv)
ciphertext, signature = cipher.encrypt_and_digest(bytes_data)


base64_ciphertext = base64.b64encode(ciphertext)
base64_signature = base64.b64encode(signature)

print(ciphertext)
print(signature)

result = {
     "ciphertext": base64_ciphertext,
     "enc_key": "<base64_data>",
     "enc_iv": "<base64_data>",
     "pubkey_hash": "<sha256_hash_base64>",
     "signature": "<base64_signature>",
     "pubkey_signature": "<base64_public_key_used_for_signature>",
     "algos": {
         "symmetric": "AES-256-GCM",
         "asymmetric": "RSA-2048",
         "hash": "SHA-256"
         }
}
