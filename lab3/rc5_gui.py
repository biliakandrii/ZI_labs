# rc5_gui.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from rc5_logic import RC5FileEncryption

class RC5GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RC5 File Encryption/Decryption")
        self.root.geometry("600x400")
        self.rc5_cipher = RC5FileEncryption()

        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.setup_widgets(main_frame)

    def setup_widgets(self, frame):
        ttk.Label(frame, text="File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.file_path = tk.StringVar()
        ttk.Entry(frame, textvariable=self.file_path, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(frame, text="Browse", command=self.browse_file).grid(row=0, column=2)

        ttk.Label(frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password = tk.StringVar()
        ttk.Entry(frame, textvariable=self.password, show="*", width=50).grid(row=1, column=1, padx=5)

        button_frame = ttk.Frame(frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=20)

        ttk.Button(button_frame, text="Encrypt", command=self.encrypt_file).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Decrypt", command=self.decrypt_file).pack(side=tk.LEFT, padx=10)

        self.progress_var = tk.StringVar()
        ttk.Label(frame, textvariable=self.progress_var).grid(row=3, column=0, columnspan=3)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)

    def encrypt_file(self):
        input_file = self.file_path.get()
        if not input_file:
            messagebox.showerror("Error", "Please select a file")
            return

        password = self.password.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return

        output_file = input_file + ".encrypted"
        try:
            self.progress_var.set("Encrypting...")
            self.root.update()
            self.rc5_cipher.encrypt_file(input_file, output_file, password)
            self.progress_var.set("File encrypted successfully!")
            messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {output_file}")
        except Exception as e:
            self.progress_var.set("Encryption failed!")
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_file(self):
        input_file = self.file_path.get()
        if not input_file:
            messagebox.showerror("Error", "Please select a file")
            return

        password = self.password.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return

        output_file = input_file + ".decrypted"
        try:
            self.progress_var.set("Decrypting...")
            self.root.update()
            self.rc5_cipher.decrypt_file(input_file, output_file, password)
            self.progress_var.set("File decrypted successfully!")
            messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {output_file}")
        except Exception as e:
            self.progress_var.set("Decryption failed!")
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

def main():
    root = tk.Tk()
    app = RC5GUI(root)
    root.mainloop()
