import base64
import json
import time
from tkinter import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Global Color and Font Scheme
BG_COLOR = "#2d2d2d"
BTN_COLOR = "#3498db"
BTN_RESET = "#27ae60"
BTN_EXIT = "#e74c3c"
TXT_COLOR = "#ecf0f1"
ENTRY_BG = "#34495e"
FONT = ('Helvetica', 14)

# User data storage (In-memory for simplicity)
users = {}

# Function to save user data to a file
def save_users():
    with open('users.json', 'w') as f:
        json.dump(users, f)

# Function to load user data from a file
def load_users():
    global users
    try:
        with open('users.json', 'r') as f:
            users = json.load(f)
    except FileNotFoundError:
        users = {}

# Load user data on startup
load_users()

# AES Encryption/Decryption
def aes_encrypt(key, plaintext):
    backend = default_backend()
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    # Padding the plaintext to ensure it's a multiple of block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt and return the ciphertext with the IV prepended
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + encrypted).decode()

def aes_decrypt(key, ciphertext):
    backend = default_backend()
    decoded_data = base64.urlsafe_b64decode(ciphertext)
    
    iv = decoded_data[:16]  # Extract IV from the ciphertext
    encrypted_message = decoded_data[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    # Decrypt the message and remove padding
    decrypted_padded = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

    return decrypted.decode()

# Key generator function (AES requires a 16-byte key for AES-128)
def generate_key_from_password(password):
    # For better security, consider using a key derivation function like PBKDF2
    return password.ljust(16).encode()[:16]

# Login function
def check_login():
    username = entry_username.get()
    password = entry_password.get()
    if username in users and users[username] == password:
        login_window.destroy()  # Close login window on success
        show_encryption_window()  # Open the encryption window
    else:
        lbl_login_error.config(text="Invalid credentials, try again!", fg="red")

# Show the encryption window after login
def show_encryption_window():
    root = Tk()
    root.geometry("800x600")
    root.title("Message Encryption and Decryption (AES)")
    root.configure(bg=BG_COLOR)

    # Center the entire content frame using pack with expand
    content_frame = Frame(root, bg=BG_COLOR)
    content_frame.pack(expand=True, fill=BOTH)

    # Top Frame for Title and Time
    header_frame = Frame(content_frame, bg=BG_COLOR)
    header_frame.pack(side=TOP, pady=20)

    # Title and time centered using pack
    lblInfo = Label(header_frame, font=('Helvetica', 28, 'bold'),
                    text="Secret Messaging\nAES Cipher",
                    fg=TXT_COLOR, bg=BG_COLOR)
    lblInfo.pack(pady=10)

    localtime = time.asctime(time.localtime(time.time()))
    lblTime = Label(header_frame, font=('Helvetica', 12),
                    text=localtime, fg=TXT_COLOR, bg=BG_COLOR)
    lblTime.pack()

    # Frame for input fields and buttons, centered
    f1 = Frame(content_frame, bg=BG_COLOR)
    f1.pack(side=TOP, pady=20)

    # Variables
    Msg = StringVar()
    key = StringVar()
    mode = StringVar()
    Result = StringVar()

    # Functions
    def qExit():
        root.destroy()

    def Reset():
        Msg.set("")
        key.set("")
        mode.set("")
        Result.set("")

    def Ref():
        clear = Msg.get()
        password = key.get()
        k = generate_key_from_password(password)
        m = mode.get()
        try:
            if m == 'e':
                encrypted_message = aes_encrypt(k, clear)
                Result.set(encrypted_message)
            elif m == 'd':
                decrypted_message = aes_decrypt(k, clear)
                Result.set(decrypted_message)
            else:
                Result.set("Invalid mode! Use 'e' or 'd'.")
        except Exception as e:
            Result.set(f"Error: {str(e)}")

    # Labels and Text Fields
    lblMsg = Label(f1, text="Message", font=FONT, bg=BG_COLOR, fg=TXT_COLOR)
    lblMsg.grid(row=1, column=0, padx=10, pady=10, sticky=E)

    txtMsg = Entry(f1, font=FONT, textvariable=Msg, bd=5, width=40, bg=ENTRY_BG, fg=TXT_COLOR)
    txtMsg.grid(row=1, column=1, padx=10, pady=10)

    lblkey = Label(f1, text="Password", font=FONT, bg=BG_COLOR, fg=TXT_COLOR)
    lblkey.grid(row=2, column=0, padx=10, pady=10, sticky=E)

    txtkey = Entry(f1, font=FONT, textvariable=key, bd=5, width=40, bg=ENTRY_BG, fg=TXT_COLOR, show="*")
    txtkey.grid(row=2, column=1, padx=10, pady=10)

    lblmode = Label(f1, text="Mode (e for encrypt, d for decrypt)", font=FONT, bg=BG_COLOR, fg=TXT_COLOR)
    lblmode.grid(row=3, column=0, padx=10, pady=10, sticky=E)

    txtmode = Entry(f1, font=FONT, textvariable=mode, bd=5, width=40, bg=ENTRY_BG, fg=TXT_COLOR)
    txtmode.grid(row=3, column=1, padx=10, pady=10)

    lblService = Label(f1, text="Result", font=FONT, bg=BG_COLOR, fg=TXT_COLOR)
    lblService.grid(row=4, column=0, padx=10, pady=10, sticky=E)

    txtService = Entry(f1, font=FONT, textvariable=Result, bd=5, width=40, bg=ENTRY_BG, fg=TXT_COLOR)
    txtService.grid(row=4, column=1, padx=10, pady=10)

    # Buttons centered
    button_frame = Frame(content_frame, bg=BG_COLOR)
    button_frame.pack(side=TOP, pady=20)

    btnShow = Button(button_frame, text="Show Message", padx=10, pady=5, bd=5, fg="white", bg=BTN_COLOR,
                     font=('Helvetica', 12, 'bold'), command=Ref)
    btnShow.grid(row=0, column=0, padx=10)

    btnReset = Button(button_frame, text="Reset", padx=10, pady=5, bd=5, fg="white", bg=BTN_RESET,
                      font=('Helvetica', 12, 'bold'), command=Reset)
    btnReset.grid(row=0, column=1, padx=10)

    btnExit = Button(button_frame, text="Exit", padx=10, pady=5, bd=5, fg="white", bg=BTN_EXIT,
                     font=('Helvetica', 12, 'bold'), command=qExit)
    btnExit.grid(row=0, column=2, padx=10)

    # Keeps window alive
    root.mainloop()

# Function to open the signup window
def open_signup_window():
    signup_window = Toplevel(login_window)
    signup_window.geometry("400x300")
    signup_window.title("Sign Up")
    signup_window.configure(bg=BG_COLOR)

    # Username and Password fields for signup
    lbl_signup_username = Label(signup_window, text="Username", font=FONT, bg=BG_COLOR, fg=TXT_COLOR)
    lbl_signup_username.pack(pady=10)

    entry_signup_username = Entry(signup_window, font=FONT, bg=ENTRY_BG, fg=TXT_COLOR, bd=5)
    entry_signup_username.pack(pady=5)

    lbl_signup_password = Label(signup_window, text="Password", font=FONT, bg=BG_COLOR, fg=TXT_COLOR)
    lbl_signup_password.pack(pady=10)

    entry_signup_password = Entry(signup_window, font=FONT, bg=ENTRY_BG, fg=TXT_COLOR, bd=5, show="*")
    entry_signup_password.pack(pady=5)

    lbl_signup_error = Label(signup_window, text="", font=('Helvetica', 12), fg="red", bg=BG_COLOR)
    lbl_signup_error.pack(pady=5)

    # Signup button
    def signup():
        username = entry_signup_username.get()
        password = entry_signup_password.get()
        if not username or not password:
            lbl_signup_error.config(text="Please enter both username and password!", fg="red")
            return
        if username in users:
            lbl_signup_error.config(text="Username already exists!", fg="red")
        else:
            users[username] = password
            save_users()  # Save user data
            signup_window.destroy()
            lbl_login_error.config(text="Signup successful! You can now log in.", fg="green")

    btn_signup = Button(signup_window, text="Sign Up", font=('Helvetica', 12, 'bold'), bg=BTN_COLOR, fg="white", bd=5, command=signup)
    btn_signup.pack(pady=20)

# Create login window
login_window = Tk()
login_window.geometry("400x300")
login_window.title("Login")
login_window.configure(bg=BG_COLOR)

# Username and Password fields
lbl_username = Label(login_window, text="Username", font=FONT, bg=BG_COLOR, fg=TXT_COLOR)
lbl_username.pack(pady=10)

entry_username = Entry(login_window, font=FONT, bg=ENTRY_BG, fg=TXT_COLOR, bd=5)
entry_username.pack(pady=5)

lbl_password = Label(login_window, text="Password", font=FONT, bg=BG_COLOR, fg=TXT_COLOR)
lbl_password.pack(pady=10)

entry_password = Entry(login_window, font=FONT, bg=ENTRY_BG, fg=TXT_COLOR, bd=5, show="*")
entry_password.pack(pady=5)

lbl_login_error = Label(login_window, text="", font=('Helvetica', 12), fg="red", bg=BG_COLOR)
lbl_login_error.pack(pady=5)

# Login button
btn_login = Button(login_window, text="Login", font=('Helvetica', 12, 'bold'), bg=BTN_COLOR, fg="white", bd=5, command=check_login)
btn_login.pack(pady=10)

# Signup button
btn_signup = Button(login_window, text="Sign Up", font=('Helvetica', 12, 'bold'), bg=BTN_COLOR, fg="white", bd=5, command=open_signup_window)
btn_signup.pack(pady=10)

# Run the window loop
login_window.mainloop()


