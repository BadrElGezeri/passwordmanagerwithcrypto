import socket
import threading
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES3
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

# File paths for storing user and password data
USERS_FILE = 'users.txt'
PASSWORDS_FILE = 'passwords.txt'
SECRET_KEY_FILE = 'secret_key.bin'

# Server RSA key generation
server_key = RSA.generate(2048)
server_public_key = server_key.publickey()
rsa_cipher = PKCS1_OAEP.new(server_key)

# Generate or load the secret key for 3DES encryption
if not os.path.exists(SECRET_KEY_FILE):
    secret_key = DES3.adjust_key_parity(os.urandom(24))  # 3DES key must be 16 or 24 bytes
    with open(SECRET_KEY_FILE, 'wb') as key_file:
        key_file.write(secret_key)
else:
    with open(SECRET_KEY_FILE, 'rb') as key_file:
        secret_key = key_file.read()

def encrypt_3des(key, plaintext):
    # Ensure the key length is compatible with 3DES (must be 16 or 24 bytes)
    key = DES3.adjust_key_parity(key)
    iv = os.urandom(8)  # Generate a random IV for 3DES
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), DES3.block_size))
    return base64.b64encode(iv + ciphertext).decode('utf-8')  # Combine IV and ciphertext, then encode

def decrypt_3des(key, ciphertext):
    # Ensure the key length is compatible with 3DES (must be 16 or 24 bytes)
    key = DES3.adjust_key_parity(key)
    data = base64.b64decode(ciphertext)
    iv = data[:8]  # Extract IV (first 8 bytes)
    ct = data[8:]  # Extract actual ciphertext
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ct), DES3.block_size)  # Unpad after decryption
    return decrypted_data.decode('utf-8')  # Convert bytes to string

# Function to receive all data from the client
def receive_full_data(client_socket):
    data = b''
    while True:
        part = client_socket.recv(1024)
        data += part
        if len(part) < 1024:
            break
    return data

# Function to handle client connections
def handle_client(client_socket):
    des_key = None
    logged_in_user = None

    # Send server's public key
    client_socket.send(server_public_key.export_key())

    # Receive and decrypt 3DES key
    encrypted_des_key = client_socket.recv(1024)
    des_key = rsa_cipher.decrypt(encrypted_des_key)

    while True:
        received_data = receive_full_data(client_socket)
        if not received_data:
            break

        try:
            decrypted_data = decrypt_3des(des_key, received_data)
        except ValueError as e:
            print(f"Decryption error: {e}")
            client_socket.send(encrypt_3des(des_key, "ERROR|Decryption failed").encode('utf-8'))
            continue

        request = decrypted_data.strip()
        action, *params = request.split('|')

        if action == "REGISTER":
            username, password = params
            if os.path.exists(USERS_FILE):
                with open(USERS_FILE, 'r') as f:
                    for line in f:
                        stored_user, _ = line.strip().split('|')
                        if stored_user == username:
                            response = "ERROR|Username already exists"
                            client_socket.send(encrypt_3des(des_key, response).encode('utf-8'))
                            break
            else:
                open(USERS_FILE, 'w').close()

            hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()
            with open(USERS_FILE, 'a') as f:
                f.write(f"{username}|{hashed_pw}\n")
            response = "SUCCESS|Registration successful"
            client_socket.send(encrypt_3des(des_key, response).encode('utf-8'))

        elif action == "LOGIN":
            username, password = params
            success = False
            if os.path.exists(USERS_FILE):
                with open(USERS_FILE, 'r') as f:
                    for line in f:
                        stored_user, stored_hash = line.strip().split('|')
                        if stored_user == username and hashlib.sha256(password.encode('utf-8')).hexdigest() == stored_hash:
                            logged_in_user = username
                            success = True
                            break

            if success:
                response = "SUCCESS|Login successful"
            else:
                response = "ERROR|Invalid username or password"
            client_socket.send(encrypt_3des(des_key, response).encode('utf-8'))

        elif action == "ADD_PASSWORD" and logged_in_user:
            platform, platform_username, platform_password = params
            encrypted_password = encrypt_3des(secret_key, platform_password)  # Encrypt using the server's secret key
            with open(PASSWORDS_FILE, 'a') as f:
                f.write(f"{logged_in_user}|{platform}|{platform_username}|{encrypted_password}\n")
            response = "SUCCESS|Password added successfully"
            client_socket.send(encrypt_3des(des_key, response).encode('utf-8'))

        elif action == "GET_PASSWORDS" and logged_in_user:
            passwords = []
            if os.path.exists(PASSWORDS_FILE):
                with open(PASSWORDS_FILE, 'r') as f:
                    for line in f:
                        parts = line.strip().split('|')
                        if len(parts) == 4:
                            stored_user, platform, platform_username, encrypted_data = parts
                            if stored_user == logged_in_user:
                                try:
                                    decrypted_data = decrypt_3des(secret_key, encrypted_data.strip())  # Decrypt using the server's secret key
                                    passwords.append(f"{platform} ({platform_username}): {decrypted_data}")
                                except ValueError as e:
                                    print(f"Skipping password due to decryption error: {e}")
                        else:
                            print(f"Skipping malformed line: {line.strip()}")
            response = f"SUCCESS|{'|'.join(passwords)}" if passwords else "ERROR|No passwords found"
            client_socket.send(encrypt_3des(des_key, response).encode('utf-8'))

        elif action == "LOGOUT":
            logged_in_user = None
            response = "SUCCESS|Logged out"
            client_socket.send(encrypt_3des(des_key, response).encode('utf-8'))

        elif action == "EXIT":
            client_socket.close()
            break

# Start server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 9999))
server.listen(5)

print("Server is running and listening for connections...")
while True:
    client_socket, addr = server.accept()
    print(f"Accepted connection from {addr}")
    client_thread = threading.Thread(target=handle_client, args=(client_socket,))
    client_thread.start()
