import tkinter as tk
from tkinter import filedialog, messagebox

def caesar_cipher(text, shift, mode='encrypt'):
    result = ""
    shift = shift % 26  # Normalize shift to be within 0-25

    if mode == 'decrypt':
        shift = -shift

    for char in text:
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            result += char  # Non-alphabetic characters are added as is

    return result

def process_text():
    mode = mode_var.get()
    text = text_entry.get("1.0", tk.END).strip()
    shift = int(shift_entry.get())
    result = caesar_cipher(text, shift, mode)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, result)

def open_file():
    file_path = filedialog.askopenfilename()
    with open(file_path, 'r') as file:
        text_entry.delete("1.0", tk.END)
        text_entry.insert(tk.END, file.read())

def save_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt")
    with open(file_path, 'w') as file:
        file.write(result_text.get("1.0", tk.END))

# GUI setup
root = tk.Tk()
root.title("MD AAMIR Caesar Cipher")

tk.Label(root, text="Enter text:", bg="black",fg="white", borderwidth=3, relief="solid").pack(pady=10)
text_entry = tk.Text(root, height=10, width=70, borderwidth=2, relief="solid")
text_entry.pack()

tk.Label(root, text="Shift:", bg="black",fg="white", borderwidth=3, relief="solid").pack(pady=10)
shift_entry = tk.Entry(root, borderwidth=2, relief="solid")
shift_entry.pack()

mode_var = tk.StringVar(value="encrypt")
tk.Radiobutton(root, text="Encrypt", variable=mode_var, value="encrypt", bg="grey",fg="white", borderwidth=3, relief="solid").pack(pady=10)
tk.Radiobutton(root, text="Decrypt", variable=mode_var, value="decrypt", bg="grey",fg="white", borderwidth=3, relief="solid").pack(pady=10)

tk.Button(root, text="Process", command=process_text, bg="purple", fg="white", borderwidth=3, relief="solid").pack(pady=5)
tk.Button(root, text="Open File", command=open_file, bg="purple", fg="white", borderwidth=3, relief="solid").pack(pady=5)
tk.Button(root, text="Save Result", command=save_file, bg="purple", fg="white", borderwidth=3, relief="solid").pack(pady=5)

tk.Label(root, text="Result:", bg="black",fg="white", borderwidth=3, relief="solid").pack(pady=5)
result_text = tk.Text(root, height=10, width=70, borderwidth=2, relief="solid")
result_text.pack()

root.mainloop()
