import json
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.Cipher import AES, PKCS1_OAEP
import glob, os, sys
from pathlib import Path

def load_message(pathfile : Path) -> bytes | dict | None:
    """
    Loads the content of a file.

    Args:
        pathfile (Path): Path to the file
    
    Returns:
        bytes | dict | None: The file content, or None if not found
    """
    type = pathfile.suffix
    try : 
        if  type == ".json":
            content = json.loads(pathfile.read_text())
        else : 
            content = pathfile.read_bytes()
        return content
    except FileNotFoundError as e:
        print("Fichier non trouvé : ", e)

def decode_base64_variables(variables_message : dict) -> dict:
    """
    Decodes all Base64-encoded variables in the message, except for the algos field.

    Args:
        variables_message(dict): Dictionary containing base64-encodedvariables

    Returns:
        dict: A dictionary with all variables decoded into bytes
    """
    variables = {}
    for k, v in variables_message.items():
        if k == "algos":
            variables[k] = v
        else :
            variables[k] = base64.b64decode(v)
    return variables

def retrieve_pubkey(raw_pubkey : bytes) -> RsaKey:
    """
    Imports a public RSA key from its PEM-encoded bytes

    Args:
        raw_pubkey (bytes): The raw PEM-encoded public key
    
    Returns:
        RsaKey: The RSA public key object
    """
    key = RSA.import_key(raw_pubkey)
    return key

def check_authenticity_integrity(pubkey : RsaKey, ciphertext : bytes, signature : bytes) -> bool:
    """
    Verifies the authenticity and integrity of a ciphertext using RSA-PSS

    Args:
        pubkey (RsaKey): The RSA public key used for signature verification
        ciphertext (bytes): The signed ciphertext.
        signature (bytes) : The RSA-PSS signature to verify
    
    Returns:
        bool True if the check is good otherwise False
    """

    h = SHA256.new(ciphertext)
    verifier = pss.new(pubkey)
    try:
        verifier.verify(h, signature)
        print("The signature is authentic.")
        return True

    except (ValueError):
        print("The signature is not authentic.")
        return False

def hash_variable(
    var
    ) -> bytes:
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

def find_all_pathfiles(working_directory : str = ".", extension : str = ".pem") -> list | None:
    """
    Finds all files with a specific ewtension in a given directory

    Args:
        working_directory (str): The dicrectory to scan (default is current)
        extension (str): File extension to look for (example - default : ".pem")
    
    Returns:
        list[Path] | None: A list of matching Path objects
    """
    try : 
        os.chdir(working_directory)
        files = list()
        for file in glob.glob("*"+extension):
            print(f"file found : {file}")
            files.append(Path(file))
        return files
    except FileNotFoundError as e:
        print("The working file doesn't exists", e)

def check_key(pathfiles : list[Path], hash_key_to_check : bytes) -> Path | None:
    """
    Checks wich key file matches a given SHA-256 hash

    Args:
        pathfiles (list[Path]): List of potential key file paths.
        hash_key_to_check (bytes): Expected SHA-256 hash of the public key

    Returns:
        Path | None: The matching key file path, or None if not found
    """
    print(hash_key_to_check)
    for pathfile in pathfiles:
        raw_key = load_message(pathfile)   
        raw_key_hash = hash_variable(raw_key)
        print(raw_key_hash)
        if hash_key_to_check == raw_key_hash:
            print("That's the one !")
            return pathfile
    
    print("No one matches !")
    return None

def find_keys_pair(pathfile_to_match : Path) -> Path:
    """
    Given a key file path (either private or public)
    returns the matching key (public - private)

    Args:
        pathfile_to_match (Path): Path to the known key file

    Returns:
        Path: The path to the paired key file
    """
    pathfile = pathfile_to_match.stem
    split_pathfile = pathfile.split("_")

    if split_pathfile[-1] == "privkey":
        split_pathfile[-1] = "pubkey"
    else:
        split_pathfile[-1] = "privkey"

    delimiter = "_"
    key_pair = delimiter.join(split_pathfile)
    key_pair_pathfile = Path(key_pair+pathfile_to_match.suffix)
    print(f"key pair found : {key_pair_pathfile}")
    return key_pair_pathfile


if __name__=="__main__":

############################################
#   Retrieving data
############################################
    # Find encrypted message with all variables and decode them with base64
    message_pathfile = Path("secure_message.json")
    message = load_message(message_pathfile)
    variables = decode_base64_variables(message)
    pprint("Variables retrieved : {variables}")    

############################################
#   Check authenticity and integrity
############################################
    pubkey_signature = retrieve_pubkey(variables["pubkey_signature"])
    # If check fails, exit the process
    if(check_authenticity_integrity(pubkey_signature, variables["ciphertext"], variables["signature"])):
        print("Authenticity and integrity verified")
    else : 
        print("Authenticity and integrity not verified")
        sys.exit(1)

############################################
#   Decrypt AES and IV
############################################
# Find the matching private key
    # Find all file with .pem, find matching key and then the path of the private key
    keys_pathfiles = find_all_pathfiles(working_directory=".", extension = ".pem")
    key_pathfile = check_key(keys_pathfiles, variables["pubkey_hash"])
    key_pair_pathfile = find_keys_pair(key_pathfile)
    print("Matching key found")

# decrypt AES and IV
    # Retrieve the passphrase and the private key
    passphrase_pathfile = Path(key_pair_pathfile.stem + ".key")
    passphrase = load_message(passphrase_pathfile)
    raw_privkey = load_message(key_pair_pathfile)
    privkey = RSA.import_key(raw_privkey, passphrase)

    # Decrypt IV and AES key
    cipher_rsa = PKCS1_OAEP.new(privkey, hashAlgo=SHA256)
    iv = cipher_rsa.decrypt(variables["enc_iv"])
    aes_key = cipher_rsa.decrypt(variables["enc_key"])
    print("iv and aes decrypted")

############################################
#   Decrypt message
############################################
    # Split tag from ciphertext
    tag = variables["ciphertext"][-16:]
    ciphertext = variables["ciphertext"][:-16]

    # Decrypt cyphertext
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    try:
        message = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        print("The message was modified!")
        sys.exit(1)

    print("Message:", message.decode())




