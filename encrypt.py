import base64
import json
from functools import wraps
from pathlib import Path
from pprint import pprint

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss

def generate_aeskey_iv(
    aes_length: int = 32, iv_length: int = 12
) -> tuple[bytes, bytes]:
    """
    Generates a 256-bit AES and a 96-bit IV for AES-GCM encryption

    Args :
        aes_length : length AES key (default : 32 octets)
        iv_length : length IV (default : 12 octets)

    Returns :
        tuple[bytes, bytes]: AES key and IV
    """
    aes_key = get_random_bytes(aes_length)
    iv = get_random_bytes(iv_length)
    return aes_key, iv

def load_data_from_file(pathfile: Path) -> bytes | str:
    """
    Loads content from a file

    Args:
        pathfile(Path) : Path to the file.

    Returns:
        bytes | str : Raw content of the file in binary or text mode
    """
    if pathfile.suffix == ".pem" or pathfile.suffix == ".key":
        return pathfile.read_bytes()
    else:
        return pathfile.read_text()

def aes_encrypt(
    plaintext: str,
    aes_key: bytes,
    iv: bytes,
) -> bytes:
    """
    Encrypts plaintext using AES-256-GCM and appends the tag.

    Args :
        plaintext (str): The plaintext to encrypt
        aes_key (bytes): AES key
        iv (bytes): Initialization vector for GCM

    Returns:
        bytes: Ciphertext
    """

    if isinstance(plaintext, str):
        b_plaintext = plaintext.encode("utf-8")

    # Encrypt text
    cipher = AES.new(aes_key, AES.MODE_GCM, iv)
    ciphertext, tag = cipher.encrypt_and_digest(b_plaintext)
    ciphertext = ciphertext + tag

    return ciphertext

def rsa_encrypt(
    var_to_encrypt: bytes,
    rsa_pubkey: RsaKey,
) -> bytes:
    """
    Encrypts data using an RSA public key.

    Args:
        var-to-encrypt (bytes): Data to encrypt
        rsa_pubkey (RsaKey): RSA public key

    Returns:
        bytes: Encrypted data
    """
    cipher_rsa = PKCS1_OAEP.new(rsa_pubkey, hashAlgo=SHA256)
    var_encrypted = cipher_rsa.encrypt(var_to_encrypt)
    return var_encrypted


def hash_variable(var) -> bytes:
    """
    Computes SHA-256 hash of a variable.

    Args:
        var (bytes): Input data.

    Returns:
        bytes: Hash
    """
    var_hash = SHA256.new(var)
    var_hash = var_hash.digest()
    return var_hash


def ciphertext_signature(
    rsa_privkey: RsaKey,
    hash: SHA256Hash,
) -> bytes:
    """
    Signes the hash using an RSA private key with PSS padding.

    Args:
        rsa_privkey (RsaKey): RSA private key
        hash (SHA256Hash): Hash to sign

    Returns:
        bytes: Signature
    """
    signature = pss.new(rsa_privkey).sign(hash)  # type: ignore[arg-type]
    return signature


def encode_in_base_64(var):
    """
    Encode variables in base64

    Args:
        var : variable to encode

    Returns:

    """
    b64_var = base64.b64encode(var).decode("utf-8")
    return b64_var


def save_message(variables: dict, pathfile: Path):
    """
    Saves a dictionary as a JSON file

    Args:
        variables (dict): Data to save
        pathfile (Path): Destination file path
    """
    pathfile.write_text(json.dumps(variables))


if __name__ == "__main__":

    variables = {}

    ############################################
    #   AES 256-GCM Encryption
    ############################################
    # Find message to encrypt
    plaintext_pathfile = Path("message.txt")
    plaintext = load_data_from_file(plaintext_pathfile)

    # Encrypt message
    aes_key, iv = generate_aeskey_iv()
    variables["ciphertext"] = aes_encrypt(plaintext, aes_key, iv)  # type: ignore[arg-type]

    ############################################
    #   Encryption of AES key and IV with RSA
    ############################################
    # Find RSA key to encrypt message
    rsa_pubkey_pathfile = Path("aes_iv_rsa_pubkey.pem")
    raw_rsa_pubkey = load_data_from_file(rsa_pubkey_pathfile)
    # Encrypt AES key and IV
    rsa_pubkey = RSA.import_key(raw_rsa_pubkey)
    variables["enc_key"] = rsa_encrypt(aes_key, rsa_pubkey)
    variables["enc_iv"] = rsa_encrypt(iv, rsa_pubkey)

    ############################################
    #   HASH public key pem file
    ############################################

    raw_pubkey = load_data_from_file(rsa_pubkey_pathfile)
    variables["pubkey_hash"] = hash_variable(raw_pubkey)

    ############################################
    #   Signature
    ############################################
    # Hash Ciphertext
    hash_ciphertext = SHA256.new(variables["ciphertext"])

    # Encrypt hashed ciphertext with RSA private key to prove authenticity and integrity
    rsa_privkey_pathfile = Path("signature_rsa_privkey.pem")
    raw_rsa_privkey = load_data_from_file(rsa_privkey_pathfile)

    # Find passphrase for rsa privkey
    rsa_privkey_passphrase_pathfile = Path("signature_rsa_privkey.key")
    passphrase = load_data_from_file(rsa_privkey_passphrase_pathfile)
    rsa_privkey = RSA.import_key(raw_rsa_privkey, passphrase)  # type: ignore[arg-type]

    # Signature
    variables["signature"] = ciphertext_signature(rsa_privkey, hash_ciphertext)

    ############################################
    #   Signature public key
    ############################################
    rsa_pubkey_pathfile = Path("signature_rsa_pubkey.pem")
    variables["pubkey_signature"] = load_data_from_file(rsa_pubkey_pathfile)

    ############################################
    #   Encode in base64
    ############################################
    variables = {k: encode_in_base_64(v) for (k, v) in variables.items()}

    ############################################
    #   Add informations
    ############################################

    algos = {"symmetric": "AES-256-GCM", "asymmetric": "RSA-2048", "hash": "SHA-256"}

    variables["algos"] = algos  # type: ignore[arg-type]

    ############################################
    #   Save message
    ############################################
    message_pathfile = Path("secure_message.json")
    save_message(variables, message_pathfile)
    print("your message has been encrypted !")
    pprint(variables)
