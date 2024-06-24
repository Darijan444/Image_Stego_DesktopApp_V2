from tkinter import *
from tkinter import filedialog, simpledialog, messagebox
import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk
import os
import base64
import secrets
from stegano import lsb
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import hashlib
 
# Create appliction window
root = Tk()
root.title("Steganography - Hide a Secret Text Message in an Image")
root.geometry("700x500+150+180")
root.resizable(False,False)
root.configure(bg = "#2f4155")
 
 
# Create a key for encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)
 
# Create a key derivation function (KDF) for password hashing
def derive_key(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
   
    password_provided = password
    password = password_provided.encode()
 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,   # Adjust this according to your security needs
        salt=salt,
        length=32    # This is the length of the derived key
    )
 
    key = kdf.derive(password)
    return key, salt
 
# AES Encryption
def aes_encrypt(message, key):
    iv = secrets.token_bytes(16)  # AES block size is 16 bytes
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = pad_message(message)
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return iv + encrypted_message  # Prepend IV to the encrypted message
 
# AES Decryption
def aes_decrypt(encrypted_message, key):
    iv = encrypted_message[:16]  # Extract the IV from the beginning
    encrypted_message = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return unpad_message(decrypted_message)
 
# Padding for AES
def pad_message(message):
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message) + padder.finalize()
    return padded_message
 
def unpad_message(padded_message):
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message
 
 
# Generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key
 
def rsa_encrypt(message, public_key):
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message
 
def rsa_decrypt(encrypted_message, private_key):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message
 
# Save RSA keys to files
def save_rsa_keys(private_key, public_key):
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("private_key.pem", "wb") as private_file:
        private_file.write(pem_private_key)
    with open("public_key.pem", "wb") as public_file:
        public_file.write(pem_public_key)
 
# Load RSA keys from files
def load_rsa_keys():
    with open("private_key.pem", "rb") as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None,
            backend=default_backend()
        )
    with open("public_key.pem", "rb") as public_file:
        public_key = serialization.load_pem_public_key(
            public_file.read(),
            backend=default_backend()
        )
    return private_key, public_key
 
 
# Updated encrypt function
def encrypt(message, password, encryption_algorithm):
    key, salt = derive_key(password)
    if encryption_algorithm == "Fernet":
        cipher_suite = Fernet(base64.urlsafe_b64encode(key))
        encrypted_message = cipher_suite.encrypt(salt + message)
    elif encryption_algorithm == "AES":
        encrypted_message = aes_encrypt(salt + message, key)
    elif encryption_algorithm == "RSA":
        private_key, public_key = generate_rsa_keys()
        save_rsa_keys(private_key, public_key)
        encrypted_message = rsa_encrypt(salt + message, public_key)
    return encrypted_message, salt
 
# Updated decrypt function
def decrypt(encrypted_message, password, salt, encryption_algorithm):
    derived_key = derive_key(password, salt)[0]
    if encryption_algorithm == "Fernet":
        cipher_suite = Fernet(base64.urlsafe_b64encode(derived_key))
        try:
            decrypted_message_bytes = cipher_suite.decrypt(encrypted_message)
            return decrypted_message_bytes
        except InvalidToken:
            print("Invalid token - decryption failed.")
            return None
    elif encryption_algorithm == "AES":
        decrypted_message_bytes = aes_decrypt(encrypted_message, derived_key)
        return decrypted_message_bytes
    elif encryption_algorithm == "RSA":
        private_key, _ = load_rsa_keys()
        decrypted_message_bytes = rsa_decrypt(encrypted_message, private_key)
        return decrypted_message_bytes
 
# Function to hash a message
def hash_message(message, algorithm):
    hash_func = hashlib.new(algorithm)
    hash_func.update(message)
    return hash_func.digest()
 
# Function to decrypt a hashed message
def decrypt_hashed_message(hashed_message, password, salt):
    derive_key = derive_key(password, salt)[0]
    cipher_suite = Fernet(derive_key)
 
    try:
        decrypted_message_bytes = cipher_suite.decrypt(hashed_message)
        return decrypted_message_bytes
    except InvalidToken:
        print("Invalid token - decryption failed.")
        return None
 
 
def save_key(filename, key):
    with open(filename, 'wb') as file:
        file.write(key.encode())
 
def read_key(filename):
    with open(filename, 'rb') as file:
        return file.read().decode()
   
# Updated save_to_file function
def save_to_file(data, filename):
    with open(filename, 'wb') as file:
        file.write(data)
 
# Updated read_from_file function
def read_from_file(filename):
    with open(filename, 'rb') as file:
        return file.read()
 
# Update save_salt function  
def save_salt(filename, salt):
    with open(filename, 'wb') as file:
        file.write(salt)
 
# Update read_salt function
def read_salt(filename):
    with open(filename, 'rb') as file:
        return file.read()
   
 
# Steganography functions
def conceal_lsb(image_path, message):
    return lsb.hide(image_path, message)
 
def reveal_lsb(image_path):
    return lsb.reveal(image_path)
 
def conceal_lsbset(image_path, message):
    # Placeholder for LSB-set method
    pass
 
def reveal_lsbset(image_path):
    # Placeholder for LSB-set method
    pass
 
def conceal_stegano(image_path, message):
    # Using Stegano's LSB method
    return lsb.hide(image_path, message)
 
def reveal_stegano(image_path):
    # Using Stegano's LSB method
    return lsb.reveal(image_path)
 
 
#icon
image_icon = PhotoImage(file = "logo_icon.png")
root.iconphoto(False,image_icon)
 
# Home Page
def home_page():
    page = Frame(root, bg="#2f4155")
    page.place(x=0, y=0, relwidth=1, relheight=1)
 
    # Title
    label = Label(page, text="Welcome to the Steganography App", bg="#2f4155", fg="white", font="arial 20 bold")
    label.pack(pady=20)      
 
    # Instructions
    instructions = Label(page, text="This app allows you to hide and reveal secret messages in images. \n The purpose of this application is safely encode and decode the images. \n The features of this application are as follows: - \n 1. To encode and decode the images. \n 2. To secure it with passwords. ", bg="#2f4155", fg="white", font="arial 10")
    instructions.pack(pady=10)
 
    # Image or Logo
    logo_img = PhotoImage(file="logo_icon.png")
    logo_label = Label(page, image=logo_img, bg="#2f4155")
    logo_label.image = logo_img
    logo_label.pack(pady=20)
 
    # Additional Information or Tips
    tips_label = Label(page, text="Tip: You can use this app to send hidden messages securely.", bg="#2f4155", fg="white", font="arial 12 italic")
    tips_label.pack(pady=10)
 
# Updated get_user_info function with multiple selections
def get_user_info():
    user_info = {}
 
    def submit():
        user_info["concealment"] = concealment_var.get()
        user_info["encryption"] = encryption_var.get()
        user_info["hash"] = hash_var.get()
        user_info["password"] = simpledialog.askstring("Password", "Set your password:", show='*')
        if user_info["password"]:
            user_info_window.destroy()
        else:
            messagebox.showerror("Input Error", "Please set a password.")
 
    def cancel():
        user_info_window.destroy()
 
    user_info_window = Toplevel(root)
    user_info_window.title("Algorithm Selection")
    user_info_window.geometry("400x300")
    user_info_window.configure(bg="#2f4155")
 
    concealment_var = StringVar(value="LSB")
    encryption_var = StringVar(value="Fernet")
    hash_var = StringVar(value="SHA256")
 
    Label(user_info_window, text="Select concealment algorithm:", bg="#2f4155", fg="white", font="arial 12").grid(row=0, column=0, pady=5, padx=10, sticky=W)
    #ttk.Combobox(user_info_window, textvariable=concealment_var, values=["LSB", "LSBSet", "ExifHeader"], state="readonly").grid(row=0, column=1, pady=5, padx=10)
    ttk.Combobox(user_info_window, textvariable=concealment_var, values=["LSB"], state="readonly").grid(row=0, column=1, pady=5, padx=10)
 
    Label(user_info_window, text="Select encryption algorithm:", bg="#2f4155", fg="white", font="arial 12").grid(row=1, column=0, pady=5, padx=10, sticky=W)
    #ttk.Combobox(user_info_window, textvariable=encryption_var, values=["Fernet", "AES", "RSA"], state="readonly").grid(row=1, column=1, pady=5, padx=10)
    ttk.Combobox(user_info_window, textvariable=encryption_var, values=["Fernet"], state="readonly").grid(row=1, column=1, pady=5, padx=10)
 
    Label(user_info_window, text="Select hash algorithm:", bg="#2f4155", fg="white", font="arial 12").grid(row=2, column=0, pady=5, padx=10, sticky=W)
    #ttk.Combobox(user_info_window, textvariable=hash_var, values=["SHA256", "SHA512", "MD5"], state="readonly").grid(row=2, column=1, pady=5, padx=10)
    ttk.Combobox(user_info_window, textvariable=hash_var, values=["SHA256"], state="readonly").grid(row=2, column=1, pady=5, padx=10)
 
    submit_button = Button(user_info_window, text="Continue", command=submit, bg="white", fg="black", font="arial 12")
    submit_button.grid(row=3, column=0, pady=20, padx=10, sticky=E)
 
    cancel_button = Button(user_info_window, text="Cancel", command=cancel, bg="white", fg="black", font="arial 12")
    cancel_button.grid(row=3, column=1, pady=20, padx=10, sticky=W)
 
    user_info_window.wait_window()
 
    if user_info:
        return user_info["concealment"], user_info["encryption"], user_info["hash"], user_info["password"]
    else:
        return None, None, None, None
 
 
# Hide and Show
def hide_show():
    page = Frame(root, bg="#2f4155")
    page.place(x=0, y=0, relwidth=1, relheight=1)
 
    Label(root, text="CYBER SCIENCE", bg="#2f4155", fg="white", font="arial 25 bold").place(x=15, y=20)
 
    concealment_algorithms = ["LSB", "LSBSet", "ExifHeader"]
    encryption_algorithms = ["Fernet", "AES", "RSA"]
    hashing_algorithms = ["SHA256", "SHA512", "MD5"]
 
    global concealment_algorithm_var, encryption_algorithm_var, hash_algorithm_var, secret
    concealment_algorithm_var = StringVar(value=concealment_algorithms[0])
    encryption_algorithm_var = StringVar(value=encryption_algorithms[0])
    hash_algorithm_var = StringVar(value=hashing_algorithms[0])
 
    secret = None  # Initialize secret as None
 
    def showimage():
        global filename
        filename = filedialog.askopenfilename(initialdir=os.getcwd(), title='Select Image File', filetype=(("PNG file", "*.png"), ("JPG file", "*.jpg"), ("All file", "*.txt")))
 
        img = Image.open(filename)
        img = ImageTk.PhotoImage(img)
        lbl.configure(image=img, width=250, height=250)
        lbl.image = img
 
    # Updated Hide function
    def Hide(concealment_algorithm, encryption_algorithm, hash_algorithm, password):
        global secret
 
        concealment_algorithm = concealment_algorithm_var.get()  # Get current selected algorithm
 
        message = text1.get(1.0, END)
        result = encrypt(message.encode(), password, encryption_algorithm)
       
        # Unpack the result tuple
        encrypted_message, salt = result
 
        if concealment_algorithm == "LSB":
            secret = conceal_lsb(filename, encrypted_message.decode('latin1'))
        elif concealment_algorithm == "LSBSet":
            secret = conceal_lsbset(filename, encrypted_message.decode('latin1'))
        elif concealment_algorithm == "ExifHeader":
            secret = conceal_stegano(filename, encrypted_message.decode('latin1'))
           
        # Save salt to file
        save_salt("salt.txt", salt)
           
        # Save encrypted message to file
        save_to_file(encrypted_message, "encrypted_message.txt")
 
    # Updated Show function
    def Show():
        password = simpledialog.askstring("Password", "Enter the password:", show='*')
 
        try:
            # Extract the encrypted message from the image
            stegano_result = lsb.reveal(filename)
 
            if not stegano_result:
                messagebox.showerror("Error", "No hidden data found in the image.")
                return
 
            # Read the salt used during encryption
            salt = read_salt("salt.txt")
            decrypted_message_bytes = decrypt(read_from_file("encrypted_message.txt"), password, salt, encryption_algorithm_var.get())
 
            if decrypted_message_bytes is None:
                messagebox.showerror("Error", "Failed to decrypt. Check your password.")
                return
 
            text1.delete(1.0, END)
            text1.insert(END, decrypted_message_bytes.decode('utf-8', errors='replace'))
 
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt: {str(e)}")
 
    def save():
        try:
            if secret:
                save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
                if save_path:
                    secret.save(save_path)
                    messagebox.showinfo("Success", "Image saved successfully.")
            else:
                messagebox.showerror("Error", "No image to save. Please hide data first.")
        except NameError:
            messagebox.showerror("Error", "No image to save. Please hide data first.")
 
    #######################################################
   
 
#######################################################
 # Frames for the Hide/Show page
 
    #first frame
    f = Frame(root,bd = 3, bg = "black", width = 340, height = 280, relief = GROOVE)
    f.place(x = 10, y = 80)
 
    lbl = Label(f, bg = "black")
    lbl.place(x = 40, y = 10)
 
    #Second Frame
    frame2 = Frame(root, bd = 3, width = 340, height = 280, bg = "white", relief = GROOVE)
    frame2.place(x = 350, y = 80)
 
    text1 = Text(frame2, font = "Robote 20", bg = "white", fg = "black", relief = GROOVE, wrap = WORD)
    text1.place(x = 0, y = 0, width = 320, height = 295)
 
    scrollbar1 = Scrollbar(frame2)
    scrollbar1.place(x = 320, y = 0, height = 300)
 
    scrollbar1.configure(command = text1.yview)
    text1.configure(yscrollcommand = scrollbar1.set)
 
    #third frame
    frame3 = Frame(root, bd = 3, bg = "#2f4155", width = 330, height = 100, relief = GROOVE)
    frame3.place(x = 10, y = 370)
 
    Button(frame3, text = "Open Image", width = 10, height = 2, font = "arial 14 bold", command = showimage).place(x = 20, y = 30)
    Button(frame3, text = "Save Image", width = 10, height = 2, font = "arial 14 bold", command = save).place(x = 180, y = 30)
    Label(frame3, text = "Picture, Image, Photo File", bg = "#2f4155", fg = "yellow").place(x = 20, y = 5)
 
    #fourth frame
    frame4 = Frame(root, bd = 3, bg = "#2f4155", width = 330, height = 100, relief = GROOVE)
    frame4.place(x = 360, y = 370)
 
    Button(frame4, text="Hide Data", width=10, height=2, font="arial 14 bold", command=lambda: Hide(*get_user_info())).place(x=20, y=30)
    Button(frame4, text = "Show Data", width = 10, height = 2, font = "arial 14 bold", command = Show).place(x = 180, y = 30)
    Label(frame4, text = "Picture, Image, Photo File", bg = "#2f4155", fg = "yellow").place(x = 20, y = 5)
 
 
# About Page
def about_page():
    page = Frame(root, bg="#2f4155")
    page.place(x=0, y=0, relwidth=1, relheight=1)
 
    # Title
    label = Label(page, text="About Us", bg="#2f4155", fg="white", font="arial 20 bold")
    label.pack(pady=20)
 
    # Description
    description = Label(page, text="Steganography Application, version 1.01.01 \n Copyright(C) 2023 Crypotography Foundation \n Licensed under GNU GPL License, Version 1 \n\n E-mail: crypotograpghyfoundation@gmail.com \n Website: https://steganographyapplication.ak.net \n\n We are a team of developers passionate about cybersecurity and digital privacy.", bg="#2f4155", fg="white", font="arial 10")
    description.pack(pady=10)
 
    # Team Members
    members_label = Label(page, text="Team Members:", bg="#2f4155", fg="white", font="arial 16 bold")
    members_label.pack(pady=10)
 
    # List of Team Members
    team_members = [
        "Darijan Zumarvic - Developer",
        "Simranpreet Kaur - Developer",
    ]
 
    for member in team_members:
        member_label = Label(page, text=member, bg="#2f4155", fg="white", font="arial 12")
        member_label.pack()
 
 
# Switch to the Home Page by default
home_page()
 
# Menu
menu = Menu(root)
root.config(menu=menu)
menu.add_command(label="Home", command=home_page)
menu.add_command(label="Hide/Show", command=hide_show)
menu.add_command(label="About Us", command=about_page)
 
 
 
 
root.mainloop()


 

