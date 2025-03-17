import socket, base64
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Client:
    def __init__(self, port):
        self.host = socket.gethostname()
        self.port = port
        self.client_socket = socket.socket()

    def connect(self):
        self.client_socket.connect((self.host, self.port))

    def generate_key_rsa(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        pem_private_key = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open("output/private_key_rsa.txt", "wb") as key_file:
            key_file.write(pem_private_key)
        pem_public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open("output/public_key_rsa.txt", "wb") as key_file:
            key_file.write(pem_public_key)

        return pem_public_key

    def send_public_key(self):
        public_key = self.generate_key_rsa()
        self.client_socket.send(len(public_key).to_bytes(4, 'big'))
        self.client_socket.send(public_key)
        print("Clé publique RSA envoyée au serveur.")

    def receive_encrypt_key_aes(self):
        key_size_data = self.client_socket.recv(4)
        key_size = int.from_bytes(key_size_data, 'big')
        encrypted_aes_key = self.client_socket.recv(key_size)

        with open("output/private_key_rsa.txt", "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        self.aes_key = self.private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Clé AES reçue et déchiffrée.")

    def receiveEncryptedFile(self):
        expected_size = self.client_socket.recv(8)
        expected_size = int.from_bytes(expected_size, 'big')
        encrypted_data = b""
        while len(encrypted_data) < expected_size:
            buffer = self.client_socket.recv(expected_size - len(encrypted_data))
            if not buffer:
                raise Exception("Erreur: fichier incomplet.")
            encrypted_data += buffer

        return encrypted_data

    def decrypt_file(self, encrypted_data):
        iv = encrypted_data[:12]  
        tag = encrypted_data[12:28]  
        ciphertext = encrypted_data[28:]  

        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext

    def receive_encrypted_hash(self, encrypted_data):
        hash_crypte = base64.b64decode(encrypted_data)
        donnee_hash = self.private_key.decrypt(
            hash_crypte,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return donnee_hash

        # hash_size_data = self.client_socket.recv(4)
        # hash_size = int.from_bytes(hash_size_data, 'big')
        # encrypted_hash = self.client_socket.recv(hash_size)

        # decrypted_hash = self.private_key.decrypt(
        #     encrypted_hash,
        #     padding.OAEP(
        #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
        #         algorithm=hashes.SHA256(),
        #         label=None
        #     )
        # )

        # print("Hash SHA-3 déchiffré reçu.")
        # return decrypted_hash

    def saveFile(self, data, filename):
        with open(filename, 'wb') as f:
            f.write(data)
        print(f"Fichier sauvegardé sous {filename}")

    def close(self):
        if self.client_socket:
            self.client_socket.close()

if __name__ == '__main__':
    client = Client(5000)
    client.connect()

    client.send_public_key()

    client.receive_encrypt_key_aes()

    encrypted_data = client.receiveEncryptedFile()

    decrypted_data = client.decrypt_file(crypte_hash)

    decrypted_hash = client.receive_encrypted_hash(decrypted_data)
    client.saveFile(decrypted_data, "output/decrypted_file.txt")

    print("Fichier déchiffré avec succès.")
    client.close()
