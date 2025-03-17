import socket, os
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes as crypt_hashes
from cryptography.hazmat.primitives import hashes as crypt_hazards

class Server:
    def __init__(self, port):
        self.host = socket.gethostname()
        self.server_socket = socket.socket()
        self.server_socket.bind((self.host, port))
        self.conn = None

    def waitForConnection(self):
        self.server_socket.listen(2)
        self.conn, address = self.server_socket.accept()
        print("Connexion de:", address)

    def receive_public_key(self):
        key_size_data = self.conn.recv(4)
        key_size = int.from_bytes(key_size_data, 'big')
        public_key_data = self.conn.recv(key_size)

        self.public_key = serialization.load_pem_public_key(public_key_data)
        print("Clé publique RSA reçue du client.")

    def encrypt_key_aes(self, filename, aes_key):
        with open(filename, "rb") as f:
            plaintext = f.read()

        iv = os.urandom(12)  
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return iv + encryptor.tag + ciphertext

    def compute_hash_sha3(self, encrypted_data):
        sha3_256 = crypt_hashes.Hash(crypt_hashes.SHA3_256())
        sha3_256.update(encrypted_data)
        return sha3_256.finalize()

    def send_encrypted_hash(self, file_encrypted_data):
        file_hash = self.compute_hash_sha3(file_encrypted_data)
        
        encrypted_hash = self.public_key.encrypt(
            file_hash,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=crypt_hazards.SHA256()),
                algorithm=crypt_hazards.SHA256(),
                label=None
            )
        )
        self.conn.send(len(encrypted_hash).to_bytes(4, 'big'))
        self.conn.send(encrypted_hash)
        print("Hash SHA-3 du fichier envoyé.")

    def send_encrypt_key_aes(self, aes_key):
        encrypted_aes_key = self.public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.conn.send(len(encrypted_aes_key).to_bytes(4, 'big'))
        self.conn.send(encrypted_aes_key)
        print("Clé AES chiffrée envoyée.")

    def sendFile(self, encrypted_data):
        self.conn.sendall(len(encrypted_data).to_bytes(8, 'big'))  # Send the file size first
        self.conn.sendall(encrypted_data)  # Send the actual file data
        print("Fichier chiffré envoyé.")


    def close(self):
        if self.conn:
            self.conn.close()

if __name__ == '__main__':
    server = Server(5000)
    server.waitForConnection()
    
    server.receive_public_key()
    
    aes_key = os.urandom(32)  
    
    encrypted_data = server.encrypt_key_aes("input/test.txt", aes_key)
    
    server.send_encrypt_key_aes(aes_key)

    server.send_encrypted_hash(encrypted_data)
    
    server.sendFile(encrypted_data)
    print(encrypted_data)

    print("Transfert terminé.")
    
    server.close()
