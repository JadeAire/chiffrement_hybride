from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
import json
import base64
from pprint import pprint

############################################
#   AES 256-GCM Encryption
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
ciphertext, tag = cipher.encrypt_and_digest(bytes_data)

############################################
#   Encryption of AES key and IV with RSA
############################################

# Retrieve RSA public key
encrypt_key_public_rsa_key = RSA.import_key(open("encrypt_text_rsa_public_key.pem", "rb").read())

# Encrypt AES and IV with rsa public key
cipher_rsa = PKCS1_OAEP.new(encrypt_key_public_rsa_key)

encrypted_aes_key = cipher_rsa.encrypt(aes_key)
encrypted_iv = cipher_rsa.encrypt(iv)

############################################
#   HASH public key pem file
############################################

h = SHA256.new()


with open("encrypt_text_rsa_public_key.pem", "rb") as f:
    # Add public key to hash
    pubkey_hash = h.update(f.read())

# Hash the public key
pubkey_hash = h.digest()

############################################
#   HASH ciphertext
############################################
ciphertext_hash = SHA256.new(ciphertext)

# Sign hash ciphertext with private key
# Retrieve RSA private key
with open("encrypt_signaturersa_private_key.pem", "rb") as f:
    signature_private_rsa_key = RSA.import_key(f.read(), "-->very secret<--")

signature = pss.new(signature_private_rsa_key).sign(ciphertext_hash) # type: ignore[arg-type]

############################################
#   Message final
############################################

# base64 encoding
base64_ciphertext = base64.b64encode(ciphertext).decode("utf-8")
base64_encrypted_aes_key = base64.b64encode(encrypted_aes_key).decode("utf-8")
base64_encrypted_iv = base64.b64encode(encrypted_iv).decode("utf-8")
base64_pubkey_hash = base64.b64encode(pubkey_hash).decode("utf-8")
base64_signature = base64.b64encode(signature).decode("utf-8")
base64_public_key = base64.b64encode(open("encrypt_signature_rsa_public_key.pem", "rb").read()).decode("utf-8")


result = {
     "ciphertext": base64_ciphertext,
     "enc_key": base64_encrypted_aes_key,
     "enc_iv": base64_encrypted_iv,
     "pubkey_hash": base64_pubkey_hash,
     "signature": base64_signature,
     "pubkey_signature": base64_public_key,
     "algos": {
         "symmetric": "AES-256-GCM",
         "asymmetric": "RSA-2048",
         "hash": "SHA-256"
         }
}

with  open("message.json", "w") as f:
    json.dump(result, f)

pprint(result)
