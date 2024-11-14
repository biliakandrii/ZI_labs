import hashlib
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext


def calculate_md5(input_string=None, file_path=None):
    md5_hash = hashlib.md5()

    if input_string is not None:
        md5_hash.update(input_string.encode('utf-8'))
    elif file_path:
        with open(file_path, 'rb') as file:
            for chunk in iter(lambda: file.read(4096), b''):
                md5_hash.update(chunk)
    else:
        raise ValueError("Either input_string or file_path must be provided")

    return md5_hash.hexdigest().upper()


def verify_file_integrity(file_path, md5_file_path):
    calculated_hash = calculate_md5(file_path=file_path)

    with open(md5_file_path, 'r') as md5_file:
        expected_hash = md5_file.read().strip().upper()

    return calculated_hash == expected_hash


class MD5App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MD5 Hash Calculator and File Integrity Verifier")
        self.geometry("600x450")

        self.create_widgets()

    def create_widgets(self):
        # String input for MD5 calculation
        tk.Label(self, text="Input String:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.string_entry = tk.Entry(self, width=50)
        self.string_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5)
        tk.Button(self, text="Calculate MD5", command=self.calculate_string_md5).grid(row=0, column=3, padx=5, pady=5)

        # File input for MD5 calculation
        tk.Label(self, text="File to Calculate Hash:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.calc_file_entry = tk.Entry(self, width=50)
        self.calc_file_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5)
        tk.Button(self, text="Browse", command=self.browse_calc_file).grid(row=1, column=3, padx=5, pady=5)
        tk.Button(self, text="Calculate File MD5", command=self.calculate_file_md5).grid(row=2, column=1, padx=5, pady=5)

        # File to verify
        tk.Label(self, text="File to Verify:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.file_entry = tk.Entry(self, width=50)
        self.file_entry.grid(row=3, column=1, columnspan=2, padx=5, pady=5)
        tk.Button(self, text="Browse", command=self.browse_file).grid(row=3, column=3, padx=5, pady=5)

        # MD5 file input
        tk.Label(self, text="MD5 Checksum File (.md5):").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        self.md5_file_entry = tk.Entry(self, width=50)
        self.md5_file_entry.grid(row=4, column=1, columnspan=2, padx=5, pady=5)
        tk.Button(self, text="Browse", command=self.browse_md5_file).grid(row=4, column=3, padx=5, pady=5)

        # Integrity check button
        tk.Button(self, text="Verify Integrity", command=self.verify_integrity).grid(row=5, column=1, padx=5, pady=5)

        # Result display
        self.result_text = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=70, height=10)
        self.result_text.grid(row=6, column=0, columnspan=4, padx=5, pady=5)

        # Save result button
        tk.Button(self, text="Save Result", command=self.save_result).grid(row=7, column=1, padx=5, pady=5)

    def calculate_string_md5(self):
        input_string = self.string_entry.get()
        result = calculate_md5(input_string=input_string)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"MD5 Hash for the string: {result}\n")

    def browse_calc_file(self):
        filename = filedialog.askopenfilename()
        self.calc_file_entry.delete(0, tk.END)
        self.calc_file_entry.insert(0, filename)

    def calculate_file_md5(self):
        file_path = self.calc_file_entry.get()
        if os.path.exists(file_path):
            result = calculate_md5(file_path=file_path)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"MD5 Hash for the file: {result}\n")
        else:
            messagebox.showerror("Error", "File not found.")

    def browse_file(self):
        filename = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, filename)

    def browse_md5_file(self):
        filename = filedialog.askopenfilename(filetypes=[("MD5 Files", "*.md5"), ("All Files", "*.*")])
        self.md5_file_entry.delete(0, tk.END)
        self.md5_file_entry.insert(0, filename)

    def verify_integrity(self):
        file_path = self.file_entry.get()
        md5_file_path = self.md5_file_entry.get()

        if not file_path or not md5_file_path:
            messagebox.showerror("Error", "Please select both the file to verify and the MD5 file.")
            return

        if os.path.exists(file_path) and os.path.exists(md5_file_path):
            try:
                is_valid = verify_file_integrity(file_path, md5_file_path)
                self.result_text.delete(1.0, tk.END)
                if is_valid:
                    self.result_text.insert(tk.END, "File integrity verified. The file is intact.\n")
                else:
                    self.result_text.insert(tk.END, "File integrity check failed. The file may be corrupted or modified.\n")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred during verification: {e}")
        else:
            messagebox.showerror("Error", "One or both files not found.")

    def save_result(self):
        result = self.result_text.get(1.0, tk.END).strip()
        if result:
            file_path = filedialog.asksaveasfilename(defaultextension=".txt")
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(result)
                messagebox.showinfo("Success", f"Result saved to {file_path}")
        else:
            messagebox.showwarning("Warning", "No result to save.")


app = MD5App()
app.mainloop()
