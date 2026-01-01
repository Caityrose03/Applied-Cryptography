
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as aes_padding
import os
import string

class CryptoProject:
    
    def vigenere_encrypt(self, message, keyword):
    # Your Vigenère cipher encryption code here

        # message should have no spaces, no punct, and all upper case. 
        # keyword needs to be all uppercase. 
        c = ''
        m = message
        strip_chars = string.punctuation + " "
        translator = str.maketrans('', '', strip_chars)
        m = m.translate(translator).upper()
        keyword = keyword.upper()

        # need to make the key the same length as the message
        # use the keyword over and over until you've reached the full length of the message. 
        # can look at message after being stripped. Find length and wrap keyword until it is the same length. 
        len(keyword) == len(m)
        while len(keyword) <len(m):
            keyword += keyword
        while len(keyword) > len(m):
            keyword = keyword[:-1]
        # Need to initiate the key index which is the current position in the message index
        key_index = 0
        key_string = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"

        # search through the message character by character and build the ciphertext letter by letter
        for i in m: 
            start_index = key_string.index(i)
            start_index += key_string.index(keyword[key_index])
            c += key_string[start_index]
            key_index += 1

        return c
    
    def vigenere_decrypt(self, ciphertext, keyword):
        # Your Vigenère cipher decryption code here
        # message should have no spaces, no punct, and all upper case. 
        # keyword needs to be all uppercase. 
        c = ciphertext
        m = ''
        keyword = keyword.upper()
        strip_chars = string.punctuation + " "
        translator = str.maketrans('', '', strip_chars)
        c = c.translate(translator).upper()
        print(c)
        while len(keyword) <len(c):
            keyword += keyword
        while len(keyword) > len(c):
            keyword = keyword[:-1]
  
        while len(keyword) < len(c):
            keyword += keyword
            keyword = keyword[:len(c)]
        # Need to initiate the key index which is the current position in the message index
        key_index = 0
        key_string = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"

        # search through the message character by character and build the plaintext letter by letter
        for i in c:
            start_index = key_string.index(i)
            start_index -= key_string.index(keyword[key_index])
            m += key_string[start_index]
            key_index += 1
        return m

    def aes_encrypt(self, plaintext, key):
    # AES encryption code here
        salt = os.urandom(16)
        iv = os.urandom(16)

        # https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
        # Need to derive a 256-bit AES key from the provided key using PBKDF2HMAC
        # this makes sure that the same key string will produce different AES keys due to the random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
         )
        aes_key = kdf.derive(key.encode())

        # Pad the plaintext to a multiple of the block size 
        # https://cryptography.io/en/latest/hazmat/primitives/padding/
        padder = aes_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        # https://cryptography.io/en/3.4.2/hazmat/primitives/symmetric-encryption.html
        # Use CBC mode
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the data 
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        # change salt, iv and ciphertext to hex
     # Return salt, iv, and ciphertext for decryption as a single string separated by '|'
        return f"{salt.hex()}|{iv.hex()}|{ciphertext.hex()}"

    def aes_decrypt(self, ciphertext, key):
    # AES decryption code here
         # Need to split the input string to get salt, iv, and ciphertext
        # Convert salt, iv, and ciphertext back to bytes
        # Derive the AES key using the same method as in encryption
        # Decrypt the ciphertext
        # Unpad the plaintext
        # Return the plaintext string

        # Split the input string to get salt, iv, and ciphertext
        # split by '|'
        salt_hex, iv_hex, ct_hex = ciphertext.split('|')

        # Convert hex strings back to bytes 
        salt = bytes.fromhex(salt_hex)
        iv = bytes.fromhex(iv_hex)
        ciphertext = bytes.fromhex(ct_hex)

        # Derive the AES key using the same method as in encryption
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        aes_key = kdf.derive(key.encode())

        # Decrypt the ciphertext
        # Create a Cipher object with the AES key and IV in CBC mode
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        # Create a decryptor object
        decryptor = cipher.decryptor()
        # Decrypt the ciphertext
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        # Unpad the plaintext returned from decryption
        unpadder = aes_padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        # Return the plaintext string
        return plaintext.decode()
  
    def rsa_encrypt(self, plaintext, public_key_path):
    # RSA encryption code here
    
        # access file to get key
        # load key from file
        # encrypt with public key
        # return ciphertext

        # load public key from file
        with open(public_key_path, "rb") as f:
            public_key_obj = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        # encrypt the plaintext using the public key
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
        ciphertext = public_key_obj.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # return ciphertext as hex string for simplicity
        return ciphertext.hex()

    def rsa_decrypt(self, ciphertext, private_key_path):
    # RSA decryption code here
        # access file to get key
        # load key from file
        # decrypt with private key
        # return plaintext

        # decrypt a hex-encoded string using RSA private key
        with open(private_key_path, "rb") as f:
            private_key_obj = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

        # convert hex string back to bytes
        ciphertext_bytes = bytes.fromhex(ciphertext)

        # decrypt the ciphertext using the private key
        plaintext = private_key_obj.decrypt(
            ciphertext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # convert plaintext back to string
        return plaintext.decode()

    def generate_rsa_keys(self):
    # RSA key generation code here
          # Need to generate a private key first, then derive the public key from it
        # Save both keys to files in PEM format
        # Then will use these keys for encryption and decryption in the rsa_encrypt and rsa_decrypt functions
        # Use one key to encrypt and the other to decrypt
        # Use padding and hashing for security during encryption and decryption

        # Logic: 
        # 1. Generate a private key using rsa.generate_private_key with public exponent 65537, key size 2048 bits, and default backend.
        # 2. Serialize and save the private key to a file in PEM format
        # 3. Generate the public key from the private key
        # 4. Serialize and save the public key to a file in PEM format
        # 5. Print a message indicating that the keys have been generated and saved.

        # Create the private key using RSA algorithm in cyptography library
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
        # need to serialize the key to save it to PEM file. 
        # save private key to file
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        # write the private key to a file
        with open("private_key.pem", "wb") as f:
            f.write(pem_private)   

        # get the public key from private key and save to file
        public_key = private_key.public_key()
        pem_public = public_key.public_bytes(
            # use PEM encoding and SubjectPublicKeyInfo format for public key
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # write the public key to a file
        with open("public_key.pem", "wb") as f:
            f.write(pem_public)   
        print("RSA keys generated and saved to 'private_key.pem' and 'public_key.pem'.")
    
        # load private key from file
        with open("private_key.pem", "rb") as f:
            # load the private key from the PEM file
            private_key = serialization.load_pem_private_key(
                # read the file contents
                f.read(),
                # no password since we did not encrypt the private key
                password=None,
                # use default backend
                backend=default_backend()
            )
        # load public key from file
        with open("public_key.pem", "rb") as f:
            # load the public key from the PEM file
            public_key = serialization.load_pem_public_key(
                # read the file contents
                f.read(),
                # use default backend
                backend=default_backend()
            )
        # return the keys
        return private_key, public_key


    def hash_string(self, input_string):
        # https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/
        # return the hex representation of the hash
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(input_string.encode())
        hash_bytes = digest.finalize()
        # return the hex representation of the hash for simplicity
        return hash_bytes.hex()

    def verify_integrity(self, input_string, expected_hash):
        # give string and expected hash. hash string and compare to expected hash. return true or false.
        input_hash = self.hash_string(input_string)
        if input_hash == expected_hash:
            return True
        else:
            return False
