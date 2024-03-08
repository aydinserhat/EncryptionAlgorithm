import tkinter as tk
from tkinter import ttk
import hashlib
import random

target_hash = 'md5'

def hash_and_encrypt():
    global target_hash
    text = entry.get()
    target_hash = hashlib.md5(text.encode()).hexdigest()
    
    # XOR key'i rastgele seç
    xor_key = random.randint(0, 20)
    
    # Target hash'i XOR key ile şifrele
    encrypted = ''.join(chr(ord(c) ^ xor_key) for c in target_hash)
    
    result_label.config(text=f'Hash: {target_hash}\nXOR Key: {xor_key}\n')
    entry2.delete(0, tk.END)
    entry2.insert(0, encrypted)

root = tk.Tk()
root.title('Hash and Encrypt')

# Stil
style = ttk.Style()
style.configure('TButton', font=('calibri', 12, 'bold'), borderwidth='4', foreground='#000000', background='#4CAF50')
style.configure('TLabel', font=('calibri', 12, 'bold'), foreground='#333333')
style.configure('TEntry', font=('calibri', 12), padding=10)

# Giriş Etiketi ve Giriş Kutusu
entry_label = ttk.Label(root, text="Enter Text:")
entry_label.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
entry = ttk.Entry(root, width=50, style='TEntry')
entry.grid(row=0, column=1, padx=10, pady=10)

# Şifrele Butonu
encrypt_button = ttk.Button(root, text='Hash and Encrypt', command=hash_and_encrypt, style='TButton')
encrypt_button.grid(row=1, column=0, columnspan=2, pady=10)

# Şifrelenmiş Metin Kutusu
entry2_label = ttk.Label(root, text="Encrypted Text:")
entry2_label.grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)
entry2 = ttk.Entry(root, width=50, style='TEntry')
entry2.grid(row=2, column=1, padx=10, pady=10)

# Sonuç Etiketi
result_label = ttk.Label(root, text='', wraplength=400, style='TLabel')
result_label.grid(row=3, column=0, columnspan=2, pady=10)

root.mainloop()
