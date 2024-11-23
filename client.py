import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES3
from Crypto.Util.Padding import pad, unpad
import base64
import tkinter as tk
from tkinter import messagebox, simpledialog

# 3DES encryption utilities
def encrypt_3des(key, plaintext):
    iv = os.urandom(8)  # Generate a random IV
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), DES3.block_size))
    return base64.b64encode(iv + ciphertext).decode('utf-8')  # Combine IV and ciphertext, then encode

def decrypt_3des(key, encrypted_data):
    raw_data = base64.b64decode(encrypted_data)  # Decode base64-encoded input
    iv = raw_data[:8]  # Extract IV
    ct = raw_data[8:]  # Extract ciphertext
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ct), DES3.block_size)
    return decrypted_data.decode('utf-8')  # Return plaintext string

# Initialize connection to server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.connect(("127.0.0.1", 9999))

# Receive server's public key
server_public_key = RSA.import_key(server.recv(1024))
rsa_cipher = PKCS1_OAEP.new(server_public_key)

# Generate 3DES key and send to server
des_key = DES3.adjust_key_parity(os.urandom(24))  # 3DES key must be 16 or 24 bytes
encrypted_des_key = rsa_cipher.encrypt(des_key)
server.send(encrypted_des_key)

# GUI Application
class PasswordManagerApp:
    def __init__(self):
        self.logged_in_user = None
        self.root = tk.Tk()
        self.root.title("Password Manager")
        self.main_menu()

    def main_menu(self):
        self.clear_window()
        tk.Label(self.root, text="Password Manager").pack(pady=10)
        tk.Button(self.root, text="Register", command=self.register).pack(pady=5)
        tk.Button(self.root, text="Login", command=self.login).pack(pady=5)

    def logged_in_menu(self):
        self.clear_window()
        tk.Label(self.root, text=f"Welcome, {self.logged_in_user}!").pack(pady=10)
        tk.Button(self.root, text="Add Password", command=self.add_password).pack(pady=5)
        tk.Button(self.root, text="Get Passwords", command=self.get_passwords).pack(pady=5)
        tk.Button(self.root, text="Logout", command=self.logout).pack(pady=5)

    def register(self):
        username = simpledialog.askstring("Register", "Enter username:")
        password = simpledialog.askstring("Register", "Enter password:")
        if username and password:
            self.send_request(f"REGISTER|{username}|{password}")

    def login(self):
        username = simpledialog.askstring("Login", "Enter username:")
        password = simpledialog.askstring("Login", "Enter password:")
        if username and password:
            self.send_request(f"LOGIN|{username}|{password}")

    def add_password(self):
        platform = simpledialog.askstring("Add Password", "Enter platform:")
        platform_username = simpledialog.askstring("Add Password", "Enter platform username:")
        platform_password = simpledialog.askstring("Add Password", "Enter password:")
        if platform and platform_username and platform_password:
            self.send_request(f"ADD_PASSWORD|{platform}|{platform_username}|{platform_password}")

    def get_passwords(self):
        self.send_request("GET_PASSWORDS")

    def logout(self):
        self.send_request("LOGOUT")
        self.logged_in_user = None
        self.main_menu()

    def send_request(self, request):
        encrypted_request = encrypt_3des(des_key, request).encode('utf-8')  # Encode to bytes
        server.send(encrypted_request)

        # Handle the response by receiving multiple parts if necessary
        encrypted_response = b''
        while True:
            part = server.recv(1024)
            encrypted_response += part
            if len(part) < 1024:
                break

        response = decrypt_3des(des_key, encrypted_response)  # Decrypt response
        action, *message = response.split('|')

        if action == "SUCCESS":
            if "Login" in message[0]:
                self.logged_in_user = request.split('|')[1]
                self.logged_in_menu()
            elif message and message[0] == "No passwords found":
                messagebox.showerror("Error", message[0])
            else:
                messagebox.showinfo("Passwords", "\n".join(message))
        else:
            messagebox.showerror("Error", message[0])

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def run(self):
        self.root.mainloop()

# Run the client app
app = PasswordManagerApp()
app.run()
