import json
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Hash.SHA256 import SHA256Hash

def load_message(pathfile : str):
    try:
        with open(pathfile, "r") as f:
            return json.load(f)
    except FileNotFoundError as e:
        print("Fichier non trouvé : ", e)

def decode_base64_variables(variables_message : dict):
    variables = {}
    for k, v in variables_message.items():
        if k == "algos":
            variables[k] = v
        else :
            variables[k] = base64.b64decode(v)
    return variables

def retrieve_pubkey(raw_pubkey : bytes) -> RsaKey:
    key = RSA.import_key(raw_pubkey)
    return key

def check_authenticity_integrity(pubkey : RsaKey, ciphertext : bytes, signature : bytes):
    h = SHA256.new(ciphertext)
    verifier = pss.new(pubkey)
    try:
        verifier.verify(h, signature)
        print("The signature is authentic.")

    except (ValueError):
        print("The signature is not authentic.")

if __name__=="__main__":

############################################
#   Retrieving data
############################################
    
    message_pathfile = "message.json"
    message = load_message(message_pathfile)
    

    variables = decode_base64_variables(message)    

############################################
#   Check authenticity and integrity
############################################
    # Authenticity
    pubkey_signature = retrieve_pubkey(variables["pubkey_signature"])
    check_authenticity_integrity(pubkey_signature, variables["ciphertext"], variables["signature"])



