from PySide6.QtWidgets import (
    QApplication, QPushButton, QVBoxLayout, QWidget, QLabel, QFileDialog, QStackedWidget, QGridLayout
)
import sys

class FileEncryptor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Encryptor")
        self.resize(500, 400)

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.encryption_methods = [
            "AES",
            "DES",
            "3DES",
            "RSA",
            "Blowfish",
            "Twofish",
            "RC4",
            "RC5",
            "RC6",
            "ECC",
            "SHA-256",
            "SHA-3",
            "MD5",
            "Chacha20",
            "Salsa20",
            "Serpent",
            "Camellia",
            "IDEA",
            "GOST",
            "TEA"
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
        file_name, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*.*)")
        if file_name:
            self.file_label.setText(f"Selected: {file_name}")
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

    def encryption_alg(self, index):
        print(f"{self.encryption_methods[index]} encryption selected")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileEncryptor()
    window.show()
    sys.exit(app.exec())