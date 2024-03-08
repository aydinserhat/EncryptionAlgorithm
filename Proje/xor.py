import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from tqdm import tqdm
import hashlib
import pyperclip

# List of supported hash types
hash_names = [
    'blake2b', 
    'blake2s', 
    'md5', 
    'sha1', 
    'sha224', 
    'sha256', 
    'sha384', 
    'sha3_224', 
    'sha3_256', 
    'sha3_384', 
    'sha3_512', 
    'sha512',
]

def crack_hash(hash, wordlist, hash_type=None):
    """Crack a hash using a wordlist.

    Args:
        hash (str): The hash to crack.
        wordlist (str): The path to the wordlist.

    Returns:
        str: The cracked hash.
    """
    hash_fn = getattr(hashlib, hash_type, None)
    if hash_fn is None or hash_type not in hash_names:
        # not supported hash type
        raise ValueError(f'[!] Invalid hash type: {hash_type}, supported are {hash_names}')
    # Count the number of lines in the wordlist to set the total
    total_lines = sum(1 for line in open(wordlist, 'r'))
    print(f"[*] Cracking hash {hash} using {hash_type} with a list of {total_lines} words.")
    # open the wordlist
    with open(wordlist, 'r') as f:
        # iterate over each line
        for line in tqdm(f, desc='Cracking hash', total=total_lines):
            if hash_fn(line.strip().encode()).hexdigest() == hash:
                return line

def browse_wordlist():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    entry_wordlist.delete(0, tk.END)
    entry_wordlist.insert(tk.END, file_path)

def crack_hash_button():
    hash_value = entry_hash.get()
    wordlist_path = entry_wordlist.get()
    hash_type = combo_hash_type.get()

    if not hash_value or not wordlist_path:
        messagebox.showerror("Error", "Please provide both hash and wordlist.")
        return

    try:
        result = crack_hash(hash_value, wordlist_path, hash_type)
        if result:
            messagebox.showinfo("Success", f"Password found: {result}")
        else:
            messagebox.showinfo("Not Found", "Password not found in the wordlist.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def decrypt_xor():
    encrypted_text = entry_encrypted.get()
    xor_key = entry_xor_key.get()

    if not encrypted_text or not xor_key:
        messagebox.showerror("Error", "Please provide both encrypted text and XOR key.")
        return

    try:
        xor_key = int(xor_key)
        decrypted = ''.join(chr(ord(c) ^ xor_key) for c in encrypted_text)
        result_label_xor.config(text=f'Decrypted Text: {decrypted}')

        # Enable copying the decrypted text to the clipboard
        result_label_xor.bind("<Button-1>", lambda e: copy_to_clipboard(decrypted))
    except ValueError:
        messagebox.showerror("Error", "XOR key must be an integer.")

# Function to copy text to clipboard
def copy_to_clipboard(text):
    pyperclip.copy(text)
    messagebox.showinfo("Copied", "Decrypted text copied to clipboard!")

# GUI setup
root = tk.Tk()
root.title("Hash Cracker")

# Style configuration
style = ttk.Style()
style.configure("TFrame", background="#f0f0f0")
style.configure("TLabel", background="#f0f0f0", font=("Arial", 11))
style.configure("TButton", background="#4caf50", foreground="#000000", font=("Arial", 11))
style.configure("TEntry", font=("Arial", 11))
style.configure("TCombobox", font=("Arial", 11))

frame = ttk.Frame(root, padding="10", style="TFrame")
frame.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))

ttk.Label(frame, text="Hash:", style="TLabel").grid(column=0, row=0, pady=5, sticky=tk.W)
entry_hash = ttk.Entry(frame, width=40)
entry_hash.grid(column=1, row=0, pady=5, sticky=tk.W)

ttk.Label(frame, text="Wordlist:", style="TLabel").grid(column=0, row=1, pady=5, sticky=tk.W)
entry_wordlist = ttk.Entry(frame, width=40)
entry_wordlist.grid(column=1, row=1, pady=5, sticky=tk.W)

button_browse = ttk.Button(frame, text="Browse", command=browse_wordlist, style="TButton")
button_browse.grid(column=2, row=1, pady=5, padx=5, sticky=tk.W)

ttk.Label(frame, text="Hash Type:", style="TLabel").grid(column=0, row=2, pady=5, sticky=tk.W)
combo_hash_type = ttk.Combobox(frame, values=hash_names, state="readonly", style="TCombobox")
combo_hash_type.set("md5")
combo_hash_type.grid(column=1, row=2, pady=5, sticky=tk.W)

button_crack_hash = ttk.Button(frame, text="Crack Hash", command=crack_hash_button, style="TButton")
button_crack_hash.grid(column=0, row=3, columnspan=2, pady=10)

# XOR Decrypter
ttk.Separator(frame, orient="horizontal").grid(column=0, row=4, columnspan=3, pady=10, sticky="ew")

ttk.Label(frame, text="Encrypted Text:", style="TLabel").grid(column=0, row=5, pady=5, sticky=tk.W)
entry_encrypted = ttk.Entry(frame, width=40)
entry_encrypted.grid(column=1, row=5, pady=5, sticky=tk.W)

ttk.Label(frame, text="XOR Key:", style="TLabel").grid(column=0, row=6, pady=5, sticky=tk.W)
entry_xor_key = ttk.Entry(frame, width=10)
entry_xor_key.grid(column=1, row=6, pady=5, sticky=tk.W)

button_decrypt_xor = ttk.Button(frame, text="Decrypt XOR", command=decrypt_xor, style="TButton")
button_decrypt_xor.grid(column=0, row=7, columnspan=2, pady=10)

result_label_xor = ttk.Label(frame, text='', style="TLabel")
result_label_xor.grid(column=0, row=8, columnspan=2, pady=10)

root.mainloop()

