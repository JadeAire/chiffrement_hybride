"""
RSA key generation Utility

This module allows you to:
- Generate a new RSA key pair (2048 bits or more)
- Export the public key as an unencrypted PEM file
- Export the private key encrypted using PBKDF2 + HMAC-SHA512 + AES-256-GCM
- Protect the private key with a passphrase

Example usage :
    text_encrypt_rsa_key = RsaKeyGeneration("encrypt_text", 2048)

"""

from getpass import getpass
from pathlib import Path

from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes


class RsaKeyGeneration:
    """
    Utility class to generate and securely export an RSA key pair.

    Attributes:
        nom (str) : Prefix used for naming the output key files
        bits (int) : RSA key size in bits
        passphrase (str) : Passphrase used to encrypt the private key

    Private Methods:
        _generate_rsa_key(bits): Generates an RSA key pair.
        _save_public_key(rsa_key): Exports and saves the public key.
        _save_private_key(rsa_key) : Exports and saves encrypted private key
        _generate_and_save_rsa_key(bits) : Orchestrates generation and export

    Output files:
        - <name>_rsa_public_key.pem: Public key in PEM format (unencrypted)
        - <name>rsa_private_key.pem: Private key in PEM format
    """

    def __init__(self, name: str, bits: int) -> None:
        """
        Initializes the RsaKeyGeneration object and immediately generates and saves the key pair

        Args:
            nom (str): Name used as a prefix for output file names
            bits (int): RSA key size in bits
            passphrase (str): Passphrase used to protec the private key
        """
        self.bits = bits
        self.name = name
        self.passphrase = get_random_bytes(32)
        self._generate_and_save_rsa_key(self.bits)

    def _generate_rsa_key(self, bits: int) -> RsaKey:
        """
        Save passphrase and generates an RSA key pair of the specified size

        Args:
            bits (int): Length of the RSA key in bits

        Returns:
            RsaKey: The generated RSA key object
        """
        return RSA.generate(bits)

    def _save_passphrase(self) -> None:
        """
        Save passphrase in a file
        """
        Path(f"{self.name}_rsa_privkey.key").write_bytes(self.passphrase)

    def _save_public_key(self, rsa_key: RsaKey) -> None:
        """
        Save public key in a pem file

        Args:
            rsa_key (RsaKey): The RSA key from wich to extract the public key
        """
        with open(f"{self.name}_rsa_pubkey.pem", "wb") as f:
            public_rsa_key = rsa_key.public_key().export_key()
            f.write(public_rsa_key)

    def _save_private_key(self, rsa_key: RsaKey) -> None:
        """
        Save encrypted RSA private key into a pem file

        Args:
            rsa_key (RsaKey): The RSA key containing the private component
        """

        with open(f"{self.name}_rsa_privkey.pem", "wb") as f:

            private_rsa_key = rsa_key.export_key(
                passphrase=self.passphrase,  # type: ignore[arg-type]
                pkcs=8,
                protection="PBKDF2WithHMAC-SHA512AndAES256-GCM",
                prot_params={"iteration_count": 131072},
            )

            f.write(private_rsa_key)

    def _generate_and_save_rsa_key(self, bits: int) -> None:
        """
        Generates an RSA key and saves both the public and private components

        Args:
            bits (int): Size of the key in bits
        """
        rsa_key = self._generate_rsa_key(bits)
        self._save_passphrase()
        self._save_public_key(rsa_key)
        self._save_private_key(rsa_key)


if __name__ == "__main__":
    text_encrypt_rsa_key = RsaKeyGeneration("aes_iv", 2048)
    signature_encrypt_rsa_key = RsaKeyGeneration("signature", 2048)
