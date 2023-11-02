import secrets
import string
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

# Function to generate a password
def generate_password(length=12, use_digits=True, use_special_chars=True):
    characters = string.ascii_letters
    if use_digits:
        characters += string.digits
    if use_special_chars:
        characters += string.punctuation

    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

# Function to copy the password to the clipboard
def copy_to_clipboard():
    try:
        selected_item = password_log.selection()[0]
        password = password_log.item(selected_item, 'values')[0]
        window.clipboard_clear()
        window.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    except IndexError:
        messagebox.showwarning("Selection Missing", "Please select a password to copy.")

# Function to generate a password and log it in the Treeview
def generate_and_log_password():
    try:
        length = int(length_var.get())
        if length <= 0:
            raise ValueError("Length must be greater than 0")
    except ValueError:
        messagebox.showwarning("Invalid Input", "Please enter a positive integer for the length.")
        return

    use_digits = use_digits_var.get() == 1
    use_special_chars = use_special_chars_var.get() == 1

    password = generate_password(length, use_digits, use_special_chars)
    password_log.insert("", "end", values=[password])

# Styling function
def set_style():
    style = ttk.Style()
    style.theme_use('clam')

    style.configure('TFrame', background='#111111')
    style.configure('TButton', background='#333333', foreground='#00FF00', borderwidth=1)
    style.map('TButton', background=[('active', '#222222')], foreground=[('active', '#00FF00')])

    style.configure('TLabel', background='#111111', foreground='#00FF00')
    style.configure('TCheckbutton', background='#111111', foreground='#00FF00')
    style.configure('TEntry', foreground='#00FF00', fieldbackground='#333333', borderwidth=1)
    
    style.configure('Treeview', background='#333333', foreground='#00FF00', fieldbackground='#333333', borderwidth=1)
    style.map('Treeview', background=[('selected', '#00FF00')], foreground=[('selected', '#111111')])
    style.configure('Treeview.Heading', foreground='#00FF00', background='#111111')

# Main window creation
if __name__ == "__main__":
    window = tk.Tk()
    window.title("Cyber Password Generator")

    set_style()

    # Frame setup
    frame = ttk.Frame(window)
    frame.pack(padx=10, pady=10)

    # Password length label and entry
    length_label = ttk.Label(frame, text="Password Length:")
    length_label.grid(row=0, column=0, sticky=tk.W)

    length_var = tk.StringVar()
    length_entry = ttk.Entry(frame, textvariable=length_var)
    length_entry.grid(row=0, column=1)

    # Checkbuttons for digits and special characters
    use_digits_var = tk.IntVar()
    use_digits_checkbox = ttk.Checkbutton(frame, text="Include Digits", variable=use_digits_var)
    use_digits_checkbox.grid(row=1, column=0, sticky=tk.W)

    use_special_chars_var = tk.IntVar()
    use_special_chars_checkbox = ttk.Checkbutton(frame, text="Include Special Characters", variable=use_special_chars_var)
    use_special_chars_checkbox.grid(row=2, column=0, columnspan=2, sticky=tk.W)

    # Generate button
    generate_button = ttk.Button(frame, text="Generate Password", command=generate_and_log_password)
    generate_button.grid(row=3, column=0, pady=10)

    # Copy button
    copy_button = ttk.Button(frame, text="Copy Password", command=copy_to_clipboard)
    copy_button.grid(row=3, column=1, pady=10)

    # Treeview to log passwords
    password_log_frame = ttk.Frame(window)
    password_log_frame.pack(padx=10, pady=10)

    password_log = ttk.Treeview(password_log_frame, columns=("Password"), show="headings")
    password_log.heading("Password", text="Generated Password")
    password_log.pack()

    # Window styling
    window.configure(bg='#111111')
    window.wm_attributes('-alpha', 0.95)  # Slightly transparent window

    window.mainloop()
