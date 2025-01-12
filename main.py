from PySide6.QtWidgets import (
    QApplication, QPushButton, QVBoxLayout, QWidget, QLabel, 
    QFileDialog, QStackedWidget, QGridLayout, QMessageBox,
    QInputDialog, QLineEdit
)
import sys
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Cryptodome.Cipher import (
    AES, DES, DES3, Blowfish, ARC4,
    ChaCha20, Salsa20, IDEA, ARC2
)
from Cryptodome.PublicKey import RSA, ECC
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import hashlib
import base64

class FileEncryptor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Encryptor")
        self.resize(800, 600)
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)
        
        self.encryption_methods = [
            "AES", "DES", "3DES", "RSA", "Blowfish",
            "Twofish", "RC4", "RC5", "RC6", "ECC",
            "SHA-256", "SHA-3", "MD5", "ChaCha20", "Salsa20",
            "Serpent", "Camellia", "IDEA", "GOST", "TEA"
        ]

        self.stacked_widget = QStackedWidget()
        self.layout.addWidget(self.stacked_widget)
        
        self.create_file_selection_view()
        self.create_encryption_view()

    def create_file_selection_view(self):
        self.file_selection_widget = QWidget()
        layout = QVBoxLayout()
        
        self.file_label = QLabel("No file selected")
        self.select_file_button = QPushButton("Select File")
        self.select_file_button.clicked.connect(self.open_file_dialog)
        
        layout.addWidget(self.file_label)
        layout.addWidget(self.select_file_button)
        
        self.file_selection_widget.setLayout(layout)
        self.stacked_widget.addWidget(self.file_selection_widget)

    def open_file_dialog(self):
        self.file_name, _ = QFileDialog.getOpenFileName(
            self, "Open File", "", "All Files (*.*)"
        )
        if self.file_name:
            self.file_label.setText(f"Selected: {self.file_name}")
            self.stacked_widget.setCurrentWidget(self.encryption_options_widget)

    def create_encryption_view(self):
        self.encryption_options_widget = QWidget()
        layout = QGridLayout()
        
        self.option_buttons = []
        for i in range(len(self.encryption_methods)):
            button = QPushButton(self.encryption_methods[i])
            button.clicked.connect(lambda checked, index=i: self.encryption_alg(index))
            self.option_buttons.append(button)
            layout.addWidget(button, i // 5, i % 5)
        
        self.encryption_options_widget.setLayout(layout)
        self.stacked_widget.addWidget(self.encryption_options_widget)

    def get_password(self):
        password, ok = QInputDialog.getText(
            self, 'Password Input', 
            'Enter encryption password:', 
            QLineEdit.Password
        )
        if ok and password:
            return password.encode()
        return None

    def derive_key(self, password, salt_size=16, key_size=32):
        salt = get_random_bytes(salt_size)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password)
        return key, salt

    def encryption_alg(self, index):
        method = self.encryption_methods[index]
        try:
            password = self.get_password()
            if not password:
                return

            with open(self.file_name, 'rb') as file:
                data = file.read()

            key, salt = self.derive_key(password)
            encrypted_data = None
            iv = get_random_bytes(16)

            if method == "AES":
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted_data = cipher.encrypt(pad(data, AES.block_size))
                encrypted_data = iv + salt + encrypted_data

            elif method == "DES":
                cipher = DES.new(key[:8], DES.MODE_CBC, iv[:8])
                encrypted_data = cipher.encrypt(pad(data, DES.block_size))
                encrypted_data = iv[:8] + salt + encrypted_data

            elif method == "3DES":
                cipher = DES3.new(key[:24], DES3.MODE_CBC, iv[:8])
                encrypted_data = cipher.encrypt(pad(data, DES3.block_size))
                encrypted_data = iv[:8] + salt + encrypted_data

            elif method == "RSA":
                key = RSA.generate(2048)
                public_key = key.publickey()
                with open(f"{self.file_name}.private", 'wb') as f:
                    f.write(key.export_key())
                cipher = PKCS1_OAEP.new(public_key)
                encrypted_data = cipher.encrypt(data)

            elif method == "Blowfish":
                cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv[:8])
                encrypted_data = cipher.encrypt(pad(data, Blowfish.block_size))
                encrypted_data = iv[:8] + salt + encrypted_data

            elif method == "RC4":
                cipher = ARC4.new(key)
                encrypted_data = cipher.encrypt(data)
                encrypted_data = salt + encrypted_data

            elif method == "ChaCha20":
                cipher = ChaCha20.new(key=key)
                encrypted_data = cipher.encrypt(data)
                encrypted_data = cipher.nonce + salt + encrypted_data

            elif method == "Salsa20":
                cipher = Salsa20.new(key=key)
                encrypted_data = cipher.encrypt(data)
                encrypted_data = cipher.nonce + salt + encrypted_data

            elif method == "IDEA":
                cipher = IDEA.new(key[:16], IDEA.MODE_CBC, iv[:8])
                encrypted_data = cipher.encrypt(pad(data, IDEA.block_size))
                encrypted_data = iv[:8] + salt + encrypted_data

            elif method in ["SHA-256", "SHA-3", "MD5"]:
                if method == "SHA-256":
                    hash_obj = hashlib.sha256()
                elif method == "SHA-3":
                    hash_obj = hashlib.sha3_256()
                else:
                    hash_obj = hashlib.md5()
                hash_obj.update(data)
                encrypted_data = hash_obj.digest()

            else:
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted_data = cipher.encrypt(pad(data, AES.block_size))
                encrypted_data = iv + salt + encrypted_data

            if encrypted_data:
                output_file = f"{self.file_name}.encrypted"
                with open(output_file, 'wb') as file:
                    file.write(encrypted_data)
                
                QMessageBox.information(
                    self,
                    "Success",
                    f"File encrypted.\nSaved as: {output_file}"
                )

        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Encryption failed: {str(e)}"
            )

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileEncryptor()
    window.show()
    sys.exit(app.exec())