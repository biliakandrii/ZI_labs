
# gui.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from rsa_crypto import RSACrypto
import os


class RSACryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA File Encryption")
        self.rsa = RSACrypto()

        # Створення вкладок
        self.notebook = ttk.Notebook(root)
        self.keys_tab = ttk.Frame(self.notebook)
        self.encrypt_tab = ttk.Frame(self.notebook)
        self.decrypt_tab = ttk.Frame(self.notebook)
        self.performance_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.keys_tab, text="Keys")
        self.notebook.add(self.encrypt_tab, text="Encrypt")
        self.notebook.add(self.decrypt_tab, text="Decrypt")
        self.notebook.pack(expand=True, fill='both', padx=5, pady=5)

        self._setup_keys_tab()
        self._setup_encrypt_tab()
        self._setup_decrypt_tab()

    def _setup_keys_tab(self):
        # Генерація ключів
        ttk.Button(self.keys_tab, text="Generate New Keys",
                   command=self._generate_keys).pack(pady=5)

        # Збереження ключів
        save_frame = ttk.LabelFrame(self.keys_tab, text="Save Keys")
        save_frame.pack(fill='x', padx=5, pady=5)

        ttk.Button(save_frame, text="Save Keys",
                   command=self._save_keys).pack(pady=5)

        # Завантаження ключів
        load_frame = ttk.LabelFrame(self.keys_tab, text="Load Keys")
        load_frame.pack(fill='x', padx=5, pady=5)

        ttk.Button(load_frame, text="Load Keys",
                   command=self._load_keys).pack(pady=5)

    def _setup_encrypt_tab(self):
        ttk.Button(self.encrypt_tab, text="Select File to Encrypt",
                   command=self._encrypt_file).pack(pady=5)

    def _setup_decrypt_tab(self):
        ttk.Button(self.decrypt_tab, text="Select File to Decrypt",
                   command=self._decrypt_file).pack(pady=5)

    def _setup_performance_tab(self):
        ttk.Label(self.performance_tab, text="File size (MB):").pack(pady=5)

        self.size_var = tk.StringVar(value="1")
        size_entry = ttk.Entry(self.performance_tab, textvariable=self.size_var)
        size_entry.pack(pady=5)

        ttk.Button(self.performance_tab, text="Run Performance Test",
                   command=self._run_performance_test).pack(pady=5)

        self.result_text = tk.Text(self.performance_tab, height=10, width=40)
        self.result_text.pack(pady=5)

    def _generate_keys(self):
        try:
            self.rsa.generate_keys()
            messagebox.showinfo("Success", "Keys generated successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate keys: {str(e)}")

    def _save_keys(self):
        try:
            private_path = filedialog.asksaveasfilename(
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem")],
                title="Save Private Key"
            )
            if not private_path:
                return

            public_path = filedialog.asksaveasfilename(
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem")],
                title="Save Public Key"
            )
            if not public_path:
                return

            self.rsa.save_keys(private_path, public_path)
            messagebox.showinfo("Success", "Keys saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save keys: {str(e)}")

    def _load_keys(self):
        try:
            private_path = filedialog.askopenfilename(
                filetypes=[("PEM files", "*.pem")],
                title="Select Private Key"
            )
            if not private_path:
                return

            public_path = filedialog.askopenfilename(
                filetypes=[("PEM files", "*.pem")],
                title="Select Public Key"
            )
            if not public_path:
                return

            self.rsa.load_keys(private_path, public_path)
            messagebox.showinfo("Success", "Keys loaded successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load keys: {str(e)}")

    def _encrypt_file(self):
        try:
            input_path = filedialog.askopenfilename(
                title="Select File to Encrypt"
            )
            if not input_path:
                return

            output_path = filedialog.asksaveasfilename(
                defaultextension=".enc",
                filetypes=[("Encrypted files", "*.enc")],
                title="Save Encrypted File"
            )
            if not output_path:
                return

            self.rsa.encrypt_file(input_path, output_path)
            messagebox.showinfo("Success", "File encrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to encrypt file: {str(e)}")

    def _decrypt_file(self):
        try:
            input_path = filedialog.askopenfilename(
                filetypes=[("Encrypted files", "*.enc")],
                title="Select File to Decrypt"
            )
            if not input_path:
                return

            output_path = filedialog.asksaveasfilename(
                title="Save Decrypted File"
            )
            if not output_path:
                return

            self.rsa.decrypt_file(input_path, output_path)
            messagebox.showinfo("Success", "File decrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt file: {str(e)}")

