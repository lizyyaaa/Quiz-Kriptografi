import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np

# Function to upload file and read content
def upload_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, 'r') as file:
            text = file.read()
        input_text.delete(1.0, tk.END)
        input_text.insert(tk.END, text)

# Vigenere Cipher
def vigenere_encrypt(plaintext, key):
    key = key.lower()
    ciphertext = ""
    key_len = len(key)
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index % key_len]) - ord('a')
            if char.isupper():
                ciphertext += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                ciphertext += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            key_index += 1  # Increment key index only for alphabetic characters
        else:
            ciphertext += char  # Keep spaces and other characters
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    key = key.lower()
    plaintext = ""
    key_len = len(key)
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % key_len]) - ord('a')
            if char.isupper():
                plaintext += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                plaintext += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            key_index += 1  # Increment key index only for alphabetic characters
        else:
            plaintext += char  # Keep spaces and other characters
    return plaintext

# Playfair Cipher
def playfair_encrypt(plaintext, key):
    key = key.lower().replace("j", "i")
    matrix = create_playfair_matrix(key)
    pairs = create_playfair_pairs(plaintext)
    ciphertext = ""
    for pair in pairs:
        ciphertext += encrypt_playfair_pair(pair, matrix)
    return ciphertext

def playfair_decrypt(ciphertext, key):
    key = key.lower().replace("j", "i")
    matrix = create_playfair_matrix(key)
    pairs = create_playfair_pairs(ciphertext)
    plaintext = ""
    for pair in pairs:
        plaintext += decrypt_playfair_pair(pair, matrix)
    return plaintext

def create_playfair_matrix(key):
    alphabet = "abcdefghiklmnopqrstuvwxyz"
    matrix = []
    for char in key:
        if char not in matrix and char in alphabet:
            matrix.append(char)
    for char in alphabet:
        if char not in matrix:
            matrix.append(char)
    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def create_playfair_pairs(plaintext):
    plaintext = plaintext.lower().replace("j", "i").replace(" ", "")  # Ignore spaces
    pairs = []
    i = 0
    while i < len(plaintext):
        a = plaintext[i]
        if i + 1 < len(plaintext):
            b = plaintext[i + 1]
            if a == b:
                pairs.append((a, 'x'))
                i += 1
            else:
                pairs.append((a, b))
                i += 2
        else:
            pairs.append((a, 'x'))
            i += 1
    return pairs

def encrypt_playfair_pair(pair, matrix):
    a, b = pair
    flat_matrix = [item for sublist in matrix for item in sublist]
    row_a, col_a = divmod(flat_matrix.index(a), 5)
    row_b, col_b = divmod(flat_matrix.index(b), 5)
    if row_a == row_b:
        return matrix[row_a][(col_a + 1) % 5] + matrix[row_b][(col_b + 1) % 5]
    elif col_a == col_b:
        return matrix[(row_a + 1) % 5][col_a] + matrix[(row_b + 1) % 5][col_b]
    else:
        return matrix[row_a][col_b] + matrix[row_b][col_a]

def decrypt_playfair_pair(pair, matrix):
    a, b = pair
    flat_matrix = [item for sublist in matrix for item in sublist]
    row_a, col_a = divmod(flat_matrix.index(a), 5)
    row_b, col_b = divmod(flat_matrix.index(b), 5)
    if row_a == row_b:
        return matrix[row_a][(col_a - 1) % 5] + matrix[row_b][(col_b - 1) % 5]
    elif col_a == col_b:
        return matrix[(row_a - 1) % 5][col_a] + matrix[(row_b - 1) % 5][col_b]
    else:
        return matrix[row_a][col_b] + matrix[row_b][col_a]

# Hill Cipher
def hill_encrypt(plaintext, key_matrix):
    key_matrix = np.array(key_matrix)
    ciphertext = ""
    plaintext = plaintext.lower().replace(" ", "")
    plaintext = [ord(c) - ord('a') for c in plaintext if c.isalpha()]
    
    while len(plaintext) % key_matrix.shape[0] != 0:
        plaintext.append(ord('x') - ord('a'))  # Padding with 'x'
    
    plaintext_matrix = np.reshape(plaintext, (-1, key_matrix.shape[0]))
    for row in plaintext_matrix:
        encrypted_row = np.dot(key_matrix, row) % 26
        ciphertext += ''.join(chr(int(val) + ord('a')) for val in encrypted_row)
    
    return ciphertext

def hill_decrypt(ciphertext, key_matrix):
    key_matrix = np.array(key_matrix)
    plaintext = ""
    ciphertext = [ord(c) - ord('a') for c in ciphertext if c.isalpha()]
    
    det = int(np.round(np.linalg.det(key_matrix))) % 26
    inv_det = pow(det, -1, 26)
    
    # Calculate inverse of key matrix
    minors = np.round(np.linalg.inv(key_matrix) * det).astype(int) % 26
    inv_key_matrix = (inv_det * minors) % 26

    while len(ciphertext) % inv_key_matrix.shape[0] != 0:
        ciphertext.append(ord('x') - ord('a'))  # Padding with 'x'

    ciphertext_matrix = np.reshape(ciphertext, (-1, inv_key_matrix.shape[0]))
    for row in ciphertext_matrix:
        decrypted_row = np.dot(inv_key_matrix, row) % 26
        plaintext += ''.join(chr(int(val) + ord('a')) for val in decrypted_row)

    # Remove trailing 'x' if it was added as padding
    if plaintext.endswith('x'):
        plaintext = plaintext[:-1]

    return plaintext

# Process function to handle encryption/decryption
def process(action):
    plaintext = input_text.get("1.0", tk.END).strip()
    key = key_entry.get().strip()
    
    if len(key) < 12:
        messagebox.showerror("Error", "Key must be at least 12 characters long.")
        return

    cipher_type = cipher_var.get()
    
    if action == "encrypt":
        if cipher_type == "Vigenere":
            result = vigenere_encrypt(plaintext, key)
        elif cipher_type == "Playfair":
            result = playfair_encrypt(plaintext, key)
        elif cipher_type == "Hill":
            key_matrix = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]  # Example key matrix
            result = hill_encrypt(plaintext, key_matrix)
    else:  # decrypt
        if cipher_type == "Vigenere":
            result = vigenere_decrypt(plaintext, key)
        elif cipher_type == "Playfair":
            result = playfair_decrypt(plaintext, key)
        elif cipher_type == "Hill":
            key_matrix = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]  # Example key matrix
            result = hill_decrypt(plaintext, key_matrix)

    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, result)

# GUI setup
root = tk.Tk()
root.title("Encrypt/Decrypt")
root.geometry("500x600")
root.configure(bg="#f0f0f0")

# Input Frame
input_frame = tk.Frame(root, bg="#f0f0f0")
input_frame.pack(pady=10)

tk.Label(input_frame, text="Input Text:", bg="#f0f0f0").pack()
input_text = tk.Text(input_frame, height=5, width=50)
input_text.pack(pady=5)

tk.Button(input_frame, text="Upload File", command=upload_file).pack(pady=5)

tk.Label(input_frame, text="Enter Key (min. 12 chars):", bg="#f0f0f0").pack()
key_entry = tk.Entry(input_frame, width=50)
key_entry.pack(pady=5)

cipher_var = tk.StringVar(value="Vigenere")
tk.OptionMenu(input_frame, cipher_var, "Vigenere", "Playfair", "Hill").pack(pady=5)

button_frame = tk.Frame(input_frame)
button_frame.pack(pady=10)

tk.Button(button_frame, text="Encrypt", command=lambda: process("encrypt")).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Decrypt", command=lambda: process("decrypt")).pack(side=tk.LEFT, padx=5)

tk.Label(input_frame, text="Output Text:", bg="#f0f0f0").pack()
output_text = tk.Text(input_frame, height=5, width=50)
output_text.pack(pady=5)

root.mainloop()
