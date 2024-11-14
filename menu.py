import os
import sys
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox


class MainMenu(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Laboratory Works Menu")
        self.geometry("300x200")

        self.create_widgets()

    def create_widgets(self):
        # Create a label
        ttk.Label(self, text="Select a laboratory work to run:").pack(pady=10)

        # Create a listbox
        self.listbox = tk.Listbox(self, width=40, height=5)
        self.listbox.pack(pady=10)

        # Populate the listbox with available lab works
        self.lab_files = self.find_lab_files()
        for lab in self.lab_files:
            self.listbox.insert(tk.END, lab)

        # Create a run button
        ttk.Button(self, text="Run Selected", command=self.run_selected).pack(pady=10)

    def find_lab_files(self):
        lab_files = []
        for root, dirs, files in os.walk("."):
            for file in files:
                if file.startswith("lab") and file.endswith(".py"):
                    lab_files.append(os.path.join(root, file))
        return lab_files

    def run_selected(self):
        selection = self.listbox.curselection()
        if selection:
            selected_lab = self.lab_files[selection[0]]
            try:
                # Run the selected lab file as a separate process
                result = subprocess.run([sys.executable, selected_lab], capture_output=True, text=True)

                if result.returncode == 0:
                    messagebox.showinfo("Success", f"Lab {selected_lab} ran successfully:\n\n{result.stdout}")
                else:
                    messagebox.showerror("Error", f"An error occurred while running {selected_lab}:\n\n{result.stderr}")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while running {selected_lab}: {str(e)}")
        else:
            messagebox.showwarning("Warning", "Please select a laboratory work to run.")


app = MainMenu()
app.mainloop()
