# main.py
import tkinter as tk
from gui import RSACryptoGUI

root = tk.Tk()
root.geometry("500x400")
app = RSACryptoGUI(root)
root.mainloop()

