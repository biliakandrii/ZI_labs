# gui_application.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from crypto import CryptoOperations
import os


class DSASignatureGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DSA Digital Signature Tool")

        # Initialize crypto operations
        self.crypto = CryptoOperations()

        # Create main container
        self.main_container = ttk.Frame(root, padding="10")
        self.main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.create_widgets()

    def create_widgets(self):
        # Key Management Section
        key_frame = ttk.LabelFrame(self.main_container, text="Key Management", padding="5")
        key_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        ttk.Button(key_frame, text="Generate Keys", command=self.generate_keys).grid(row=0, column=0, padx=5)
        ttk.Button(key_frame, text="Save Keys", command=self.save_keys).grid(row=0, column=1, padx=5)
        ttk.Button(key_frame, text="Load Keys", command=self.load_keys).grid(row=0, column=2, padx=5)

        # Text Input Section
        text_frame = ttk.LabelFrame(self.main_container, text="Text Signing", padding="5")
        text_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        self.text_input = tk.Text(text_frame, height=4, width=50)
        self.text_input.grid(row=0, column=0, pady=5)

        ttk.Button(text_frame, text="Sign Text", command=self.sign_text).grid(row=1, column=0, pady=5)

        # File Operations Section
        file_frame = ttk.LabelFrame(self.main_container, text="File Operations", padding="5")
        file_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        ttk.Button(file_frame, text="Sign File", command=self.sign_file).grid(row=0, column=0, padx=5)
        ttk.Button(file_frame, text="Verify File Signature", command=self.verify_file).grid(row=0, column=1, padx=5)

        # Results Section
        result_frame = ttk.LabelFrame(self.main_container, text="Results", padding="5")
        result_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        self.result_text = tk.Text(result_frame, height=10, width=50)
        self.result_text.grid(row=0, column=0, pady=5)

        ttk.Button(result_frame, text="Save Results", command=self.save_results).grid(row=1, column=0, pady=5)

    def generate_keys(self):
        try:
            self.crypto.generate_key_pair()
            self.show_result("Keys generated successfully")
        except Exception as e:
            self.show_error(f"Error generating keys: {str(e)}")

    def save_keys(self):
        try:
            directory = filedialog.askdirectory()
            if directory:
                private_path = os.path.join(directory, "private_key.pem")
                public_path = os.path.join(directory, "public_key.pem")
                self.crypto.save_keys(private_path, public_path)
                self.show_result(f"Keys saved to:\nPrivate: {private_path}\nPublic: {public_path}")
        except Exception as e:
            self.show_error(f"Error saving keys: {str(e)}")

    def load_keys(self):
        try:
            private_path = filedialog.askopenfilename(title="Select Private Key", filetypes=[("PEM files", "*.pem")])
            if not private_path:
                return

            public_path = filedialog.askopenfilename(title="Select Public Key", filetypes=[("PEM files", "*.pem")])
            if not public_path:
                return

            self.crypto.load_keys(private_path, public_path)
            self.show_result("Keys loaded successfully")
        except Exception as e:
            self.show_error(f"Error loading keys: {str(e)}")

    def sign_text(self):
        try:
            text = self.text_input.get("1.0", tk.END).strip()
            if not text:
                self.show_error("Please enter text to sign")
                return

            signature = self.crypto.sign_data(text.encode())
            hex_signature = signature.hex()

            # Save signature to file
            file_path = filedialog.asksaveasfilename(
                defaultextension=".sig",
                filetypes=[("Signature files", "*.sig")]
            )
            if file_path:
                with open(file_path, "w") as f:
                    f.write(hex_signature)

            self.show_result(f"Text signed successfully\nSignature (hex):\n{hex_signature}")
        except Exception as e:
            self.show_error(f"Error signing text: {str(e)}")

    def sign_file(self):
        try:
            file_path = filedialog.askopenfilename(title="Select File to Sign")
            if not file_path:
                return

            signature = self.crypto.sign_file(file_path)
            hex_signature = signature.hex()

            # Save signature
            sig_path = file_path + ".sig"
            with open(sig_path, "w") as f:
                f.write(hex_signature)

            self.show_result(
                f"File signed successfully\nSignature saved to: {sig_path}\nSignature (hex):\n{hex_signature}")
        except Exception as e:
            self.show_error(f"Error signing file: {str(e)}")

    def verify_file(self):
        try:
            # Select file to verify
            file_path = filedialog.askopenfilename(title="Select File to Verify")
            if not file_path:
                return

            # Select signature file
            sig_path = filedialog.askopenfilename(
                title="Select Signature File",
                filetypes=[("Signature files", "*.sig")]
            )
            if not sig_path:
                return

            # Read signature
            with open(sig_path, "r") as f:
                hex_signature = f.read().strip()
                signature = bytes.fromhex(hex_signature)

            # Verify
            is_valid = self.crypto.verify_file_signature(file_path, signature)
            self.show_result("Signature is valid!" if is_valid else "Signature is invalid!")
        except Exception as e:
            self.show_error(f"Error verifying signature: {str(e)}")

    def save_results(self):
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")]
            )
            if file_path:
                with open(file_path, "w") as f:
                    f.write(self.result_text.get("1.0", tk.END))
                messagebox.showinfo("Success", "Results saved successfully")
        except Exception as e:
            self.show_error(f"Error saving results: {str(e)}")

    def show_result(self, message):
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert("1.0", message)

    def show_error(self, message):
        messagebox.showerror("Error", message)


