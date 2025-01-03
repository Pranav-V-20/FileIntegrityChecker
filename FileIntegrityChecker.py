import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib

# Function to compute the hash of a file
def compute_hash(file_path, algorithm):
    try:
        hash_func = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        messagebox.showerror("Error", f"Could not compute hash: {e}")
        return None

# Function to open file dialog and select a file
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

# Function to handle reference hash generation
def generate_reference_hash():
    file_path = file_entry.get()
    algorithm = algo_var.get()

    if not file_path:
        messagebox.showerror("Error", "Please select a file.")
        return

    file_hash = compute_hash(file_path, algorithm)
    if file_hash:
        ref_hash_entry.delete(0, tk.END)
        ref_hash_entry.insert(0, file_hash)
        messagebox.showinfo("Hash Generated", f"Reference hash generated using {algorithm}.")

# Function to handle hash computation and comparison
def check_integrity():
    file_path = file_entry.get()
    ref_hash = ref_hash_entry.get().strip()
    algorithm = algo_var.get()

    if not file_path or not ref_hash:
        messagebox.showerror("Error", "Please select a file and enter or generate a reference hash.")
        return

    file_hash = compute_hash(file_path, algorithm)
    if file_hash:
        result_text.set(f"Computed Hash: {file_hash}")
        if file_hash == ref_hash:
            messagebox.showinfo("Integrity Check", "File integrity verified!")
        else:
            messagebox.showwarning("Integrity Check", "File integrity check failed!")

# GUI setup
root = tk.Tk()
root.title("File Integrity Checker")

# File selection
tk.Label(root, text="File:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
file_entry = tk.Entry(root, width=50)
file_entry.grid(row=0, column=1, padx=5, pady=5)
tk.Button(root, text="Browse", command=select_file).grid(row=0, column=2, padx=5, pady=5)

# Reference hash input or generation
tk.Label(root, text="Reference Hash:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
ref_hash_entry = tk.Entry(root, width=50)
ref_hash_entry.grid(row=1, column=1, padx=5, pady=5)
tk.Button(root, text="Generate", command=generate_reference_hash).grid(row=1, column=2, padx=5, pady=5)

# Algorithm selection
tk.Label(root, text="Algorithm:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
algo_var = tk.StringVar(value="sha256")
algo_menu = tk.OptionMenu(root, algo_var, "md5", "sha1", "sha256", "sha512")
algo_menu.grid(row=2, column=1, padx=5, pady=5, sticky="w")

# Check integrity button
tk.Button(root, text="Check Integrity", command=check_integrity).grid(row=3, column=1, padx=5, pady=10)

# Result display
result_text = tk.StringVar()
result_label = tk.Label(root, textvariable=result_text, fg="blue", wraplength=400, justify="left")
result_label.grid(row=4, column=0, columnspan=3, padx=5, pady=5)

root.mainloop()
