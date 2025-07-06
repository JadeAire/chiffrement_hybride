from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
import json
import base64
from pprint import pprint
from functools import wraps
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Hash.SHA256 import SHA256Hash

def start_end_function(func):
    """
    Decorator that logs the start and the end of a function execution,
    and prints the function's returned result.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        print(f"----------Start {func.__name__}----------")
        result = func(*args, **kwargs)
        pprint(result)
        print(f"----------End {func.__name__}------------")
        return result
    return wrapper

def encode_in_base_64(func):
    """
    Decorator that encodes the first returned variable in base64.
    """
    def wrapper(*args, **kwargs):
        var, key, variables = func(*args, **kwargs)
        b_var = base64.b64encode(var).decode("utf-8")
        return b_var, key, variables
    return wrapper

def add_variable_to_dict():
    """
    Decorator that adds the (key, var) pair to the provided dictionary.
    """
    def decorator(func): 
        def wrapper(*args, **kwargs):
            var, key, variables = func(*args, **kwargs)
            print(f"Add {key} : {var} to dict")
            variables[key] = var
            return variables
        return wrapper
    return decorator

@start_end_function
def generate_aeskey_iv() -> tuple[bytes, bytes]:
    """
    Genertaes a 256-bit AES and a 96-bit IV for AES-GCM encryption

    Returns :
        tuple[bytes, bytes]: AES key and IV
    """
    aes_key = get_random_bytes(32)
    iv = get_random_bytes(12)
    return aes_key, iv

@start_end_function
def load_data_from_file(pathfile : str) -> bytes | str:
    """
    Loads content from a file

    Args:
        pathfile(str) : Path to the file.
    
    Returns:
        bytes | str : Raw contetn of the file in binary or text mode
    """
    x, type = pathfile.split(".")
    if type == "pem":
        with open(pathfile, "rb") as f:
            return f.read()
    else:
        with open(pathfile, "r") as f:
            return f.read()

@start_end_function
@add_variable_to_dict()
@encode_in_base_64
def aes_encrypt(
    plaintext : str, 
    aes_key : bytes, 
    iv : bytes, 
    key_name: str, 
    variables : dict
    ) -> tuple[bytes, str, dict]:
    """
    Encrypts plaintext using AES-256-GCM and appends the tag.
    Use decorator to encode in base64 and add to a dictionary.

    Args :
        plaintext (str): The plaintext to encrypt
        aes_key (bytes): AES key
        iv (bytes): Initialization vector for GCM
        key_name(str): key name to store the result
    
    Returns:
        tuples[bytes, str, dict]: Ciphertext + tag, key name, and updated dictionary
    """

    if isinstance(plaintext, str):
        b_plaintext = plaintext.encode("utf-8")

    # Encrypt text
    cipher = AES.new(aes_key, AES.MODE_GCM, iv)
    ciphertext, tag = cipher.encrypt_and_digest(b_plaintext)
    ciphertext = ciphertext + tag

    return ciphertext, key_name, variables # type: ignore[arg-type]

@start_end_function
@add_variable_to_dict()
@encode_in_base_64
def rsa_encrypt(
    var_to_encrypt: bytes, 
    rsa_pubkey: RsaKey, 
    key_name: str, 
    variables: dict
    ) -> tuple[bytes, str, dict]:
    """
    Encrypts data using an RSA public key. Use decorator to encode in base64 and add to a dictionary.

    Args:
        var-to-encrypt (bytes): Data to encrypt
        rsa_pubkey (RsaKey): RSA public key
        key_name (str): Key name to store the result
        variables (dict): Dictionary to store the result

    Returns:
        tuple[bytes, str, dict]: Encrypted data, key name, and updated dictionary
    """
    cipher_rsa = PKCS1_OAEP.new(rsa_pubkey)
    var_encrypted = cipher_rsa.encrypt(var_to_encrypt)
    return var_encrypted, key_name, variables

@start_end_function
@add_variable_to_dict()
@encode_in_base_64    
def hash_variable(
    var, 
    key : str, 
    variables : dict
    ) -> tuple[bytes, str, dict]:
    """
    Computes SHA-256 hash of a variable. Use decorator to encode in base64 and add to a dictionary.

    Args:
        var (bytes): Input data.
        key (str): Key name to store the result
        variables (dict): Dictionary to store the result
    
    Returns:
        tuple[bytes, str, dict]: Hash, key name, and updated dictionary
    """
    var_hash = SHA256.new(var)
    var_hash = var_hash.digest()
    return var_hash, key, variables

@start_end_function
@add_variable_to_dict()
@encode_in_base_64
def ciphertext_signature(
    rsa_privkey : RsaKey,
    hash : SHA256Hash,
    key : str,
    variables : dict
) -> tuple[bytes, str, dict]:
    """
    Signes the hash using an RSA private key with PSS padding. Use decorator to encode in base64 and add to a dictionary.

    Args:
        rsa_privkey (RsaKey): RSA private key
        hash (SHA256Hash): Hash to sign
        key (str): Key name to store the signature
        variables (dict): Dictionary to store the result
    
    Returns:
        tuple[bytes, str, dict]: Signature, key name, and updates dictionary
    """
    signature = pss.new(rsa_privkey).sign(hash) # type: ignore[arg-type]
    return signature, key, variables

@start_end_function
@add_variable_to_dict()
@encode_in_base_64
def basic_bas64_transformation(var : bytes | str, key : str, variables : dict) -> tuple[bytes, str, dict] :
    """
    Use decorator to encode in base64 and add to a dictionary.
    """
    return var, key, variables
    

def save_message(variables : dict, pathfile : str):
    """
    Saves a dictionary as a JSON file

    Args:
        variables (dict): Data to save
        pathfil (str): Destination file path
    """
    with  open(pathfile, "w") as f:
        json.dump(variables, f)


if __name__ == "__main__":

    message = {}

############################################
#   AES 256-GCM Encryption
############################################

    plaintext_pathfile = "plaintext.txt"
    plaintext = load_data_from_file(plaintext_pathfile)
    aes_key, iv = generate_aeskey_iv()
    message = aes_encrypt(plaintext, aes_key, iv, "ciphertext", message) # type: ignore[arg-type]

############################################
#   Encryption of AES key and IV with RSA
############################################

    rsa_pubkey_pathfile = "aes_iv_rsa_pubkey.pem"
    raw_rsa_pubkey = load_data_from_file(rsa_pubkey_pathfile)
    rsa_pubkey = RSA.import_key(raw_rsa_pubkey)
    message = rsa_encrypt(aes_key, rsa_pubkey, "enc_key", message) # type: ignore[arg-type]
    message = rsa_encrypt(iv, rsa_pubkey, "enc_iv", message) # type: ignore[arg-type]

############################################
#   HASH public key pem file
############################################

    raw_pubkey = load_data_from_file(rsa_pubkey_pathfile)
    message = hash_variable(raw_pubkey, "pubkey_hash", message) # type: ignore[arg-type]


############################################
#   Signature
############################################
    hash_ciphertext = SHA256.new(base64.b64decode(message["ciphertext"])) # type: ignore[arg-type]
    
    rsa_privkey_pathfile = "signature_rsa_privkey.pem"
    raw_rsa_privkey = load_data_from_file(rsa_privkey_pathfile)
    rsa_privkey = RSA.import_key(raw_rsa_privkey, "-->very secret<--")

    message = ciphertext_signature(rsa_privkey, hash_ciphertext, "signature", message)

############################################
#   Signature public key
############################################
    rsa_pubkey_pathfile = "signature_rsa_pubkey.pem"
    raw_signature_rsa_pubkey = load_data_from_file(rsa_pubkey_pathfile)
    message = basic_bas64_transformation(raw_signature_rsa_pubkey, "pubkey_signature", message)

############################################
#   Signature public key
############################################

    algos = {
            "symmetric": "AES-256-GCM",
            "asymmetric": "RSA-2048",
            "hash": "SHA-256"
    }

    message["algos"] = algos

    message_pathfile = "message.json"
    save_message(message, message_pathfile)

