import base64
import os
import random
import string

from tkinter import messagebox
from tkinter import *
from tkinter import ttk

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


def reset_keys():
    # Generate Fernet key if using Fernet
    if v.get() == 2 or v.get() == 3:
        generate_fern_key()
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(get_pwd())
    )

    # Enter private and public key generated into files
    try:
        with open(userPrivKey.get(), 'wb') as f:
            f.write(priv_pem)

        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(userPublicKey.get(), 'wb') as f:
            f.write(pub_pem)
    except FileNotFoundError:
        messagebox.showerror("File Not Found",
                             "ERROR: Filename not found in current directory...")

    root.update()
    messagebox.showinfo("Reset Successful!", "The public and private keys have been reset!")


def get_pwd():
    # If user specified password, use that, otherwise generate random string
    if len(userPassword.get()) > 0:
        return bytes(userPassword.get(), 'utf-8')

    # Generate new random password if user did not specify one
    return bytes(''.join(
        random.SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in
        range(15)), 'utf-8')


def get_priv_key():
    # If user did not specify private key filename return error
    if len(userPrivKey.get()) < 1:
        root.update()
        messagebox.showerror("Private Key Error",
                             "ERROR: Private Key name not specified...")
    try:
        # Get private key from file
        with open(userPrivKey.get(), "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=get_pwd(),
                backend=default_backend()
            )
        return private_key
    # If filename specified by user but not found return error
    except FileNotFoundError:
        root.update()
        messagebox.showerror("Missing Private Key",
                             "WARNING: Without private key, previous encrypted messages will not "
                             "be able to be decrypted...")
        return -1
    # If filename specified by user is correct but password is not return error
    except ValueError:
        root.update()
        messagebox.showerror("Private Key Error",
                             "Ensure correct password for private key is used...")
        return -1


def get_pub_key():
    # If user did not specify public key filename return error
    if len(userPublicKey.get()) < 1:
        root.update()
        messagebox.showerror("Public Key Error",
                             "ERROR: Public Key name not specified...")
        return
    try:
        # Get public key from file
        with open(userPublicKey.get(), "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key
    # If filename specified by user but not found return error
    except FileNotFoundError:
        root.update()
        messagebox.showwarning("Missing Public Key", "No public key provided, generate one or move to current file "
                                                     "directory...")
        return -1


def get_message():
    # If user entered a message filename, use that, otherwise use textbox
    if len(userMessageFile.get()) > 0:
        try:
            # Get message key from file
            f = open(userMessageFile.get(), 'rb')
            message = f.read()
            f.close()
            return message
        # If filename specified by user but not found return error
        except FileNotFoundError:
            root.update()
            messagebox.showerror("File Not Found",
                                 "ERROR: Filename not found in current directory...")
            return -1
    else:
        # If textbox does not contain any text return error, return text in bytes if text found
        if len(bytes(messageTxt.get("1.0", END), 'utf-8')) < 2:
            root.update()
            messagebox.showerror("Message Error",
                                 "ERROR: Message filename or text not specified...")
            return -1
        return bytes(messageTxt.get("1.0", END), 'utf-8')


def generate_pub_key():
    # Get private key, if not found return error
    private_key = get_priv_key()
    if private_key == -1:
        return

    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # If user specified filename, use that, otherwise return error
    if len(userPublicKey.get()) > 0:
        with open(userPublicKey.get(), 'wb') as f:
            f.write(pub_pem)
    else:
        root.update()
        messagebox.showerror("Public Key Error",
                             "ERROR: Public Key name not specified...")
        return


def encrypt_message():
    # Get message, if none found return error
    message = get_message()
    if message == -1:
        return -1

    # If Fernet selected:
    if v.get() == 2 or v.get() == 3:
        key = get_fernet_key()
        if key == -1:
            return
        encrypt_fern_key()
        return

    # If RSA selected:
    if v.get() == 1:
        try:
            public_key = get_pub_key()
            if public_key == -1:
                return

            encrypted = public_key.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                ))

            # Enter encrypted message into user specified file
            with open(userEncryptedName.get(), 'wb') as f:
                f.write(encrypted)
            root.update()
            messagebox.showinfo("Encryption Successful!",
                                "The message has been encrypted and placed in " + userEncryptedName.get() + " file!")
            # If user specified file not in current directory, return error
        except FileNotFoundError:
            root.update()
            messagebox.showerror("File Not Found",
                                 "ERROR: Encrypted Filename not found in current directory...")
            # If encryption failed, return error
        except ValueError:
            root.update()
            messagebox.showerror("Encryption Error",
                                 "Encryption of selected file FAILED, please ensure you are using correct keys and "
                                 "message filename...")


def decrypt_message():
    # If Fernet selected:
    if v.get() == 2 or v.get() == 3:
        key = get_fernet_key()
        if key == -1:
            return
        decrypt_fern_key()
        return

    # If RSA selected:
    if v.get() == 1:
        try:
            # If private key not found, return error
            private_key = get_priv_key()
            if private_key == -1:
                return

            # Get encrypted message from user specified file
            f = open(userEncryptedName.get(), 'rb')
            encrypted = f.read()
            f.close()

            original_message = private_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                ))

            # Enter decrypted message into user specified filename
            with open(userDecryptedName.get(), 'wb') as f:
                f.write(original_message)

            # Show Success Message
            root.update()
            messagebox.showinfo("Decryption Successful!",
                                "The message has been decrypted and placed in " + userDecryptedName.get() + " file!")
            return

        # If user specified file not in current directory, return error
        except FileNotFoundError:
            root.update()
            messagebox.showerror("File Not Found",
                                 "ERROR: Encrypted and/or Decrypted Filename not found in current directory...")

        # If decryption failed, return error
        except ValueError:
            root.update()
            messagebox.showerror("Decryption Error",
                                 "Decryption of selected file FAILED, please ensure you are using correct keys...")


def generate_fern_key():
    key = -1

    # If basic fernet key generation
    if v.get() == 2:
        key = Fernet.generate_key()

    # If fernet generation with password
    if v.get() == 3:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(get_pwd()))

    # If user has not specified fernet key name, return error
    if len(userPrivKey.get()) < 1 or key == -1:
        root.update()
        messagebox.showerror("Fernet Key Error",
                             "Fernet key filename not specified..")
        return -1

    # Enter fernet key into user specified file
    with open(userPrivKey.get(), "wb") as file:
        file.write(key)


def encrypt_fern_key():
    fern = Fernet(get_fernet_key())
    encrypted = fern.encrypt(get_message())

    # If user has not specified encrypted name, return error
    if len(userEncryptedName.get()) < 1:
        root.update()
        messagebox.showerror("Fernet Encryption",
                             "Fernet encrypted message filename not specified..")
        return -1

    # Enter encrypted message into user specified file
    with open(userEncryptedName.get(), 'wb') as file:
        file.write(encrypted)

    # Show Success Message
    root.update()
    messagebox.showinfo("Encryption Successful!",
                        "The message has been encrypted and placed in " + userDecryptedName.get() + " file!")


def decrypt_fern_key():
    fern = Fernet(get_fernet_key())

    # If user has not specified encrypted name, return error
    if len(userEncryptedName.get()) < 1:
        root.update()
        messagebox.showerror("Fernet Encryption",
                             "Fernet encrypted message filename not specified..")
        return -1

    # If user has specified encrypted name, attempt to get encrypted message
    # If file name not found, return error
    try:
        file = open(userEncryptedName.get(), 'rb')
        message = file.read()
        file.close()
    except FileNotFoundError:
        root.update()
        messagebox.showerror("File Not Found",
                             "Encrypted message not found in current directory...")
        return -1
    try:
        original_message = fern.decrypt(message)

        # If user has not specified decrypted message filename, return error
        if len(userDecryptedName.get()) < 1:
            root.update()
            messagebox.showerror("Fernet Decryption",
                                 "Fernet decrypted message filename not specified..")
            return -1

        # Enter message into user specified filename
        with open(userDecryptedName.get(), 'wb') as file:
            file.write(original_message)
    # If incorrect key used, return error
    except cryptography.fernet.InvalidToken:
        root.update()
        messagebox.showerror("Decryption Failed",
                             "Decryption of selected file FAILED, please ensure you are using correct keys...")
        return -1

    # Show Success Message
    root.update()
    messagebox.showinfo("Decryption Successful!",
                        "The message has been decrypted and placed in " + userDecryptedName.get() + " file!")


def get_fernet_key():
    try:
        # Get fernet key from user specified file
        file = open(userPrivKey.get(), 'rb')
        key = file.read()
        file.close()
        return key

    # If user specified fernet key is not found, return error
    except FileNotFoundError:
        root.update()
        messagebox.showerror("Missing Private Key",
                             "WARNING: Without private key, previous encrypted messages will not "
                             "be able to be decrypted...")
        return -1


def fernet_selected():
    # Disable public key entry and generation
    if userPrivKey["state"] == "normal":
        userPublicKey.config(state='disabled')
    generate_pub_bttn.config(state='disabled')

    # Change private key label and file name to Fernet
    privKeylbl.config(text="Fernet Key Filename:")
    if v.get() == 3:
        privKeyName.set("priv_fernet.key")
    else:
        privKeyName.set("fernet.key")
    new_keys.set("Gen Fernet Key")


def rsa_selected():
    # Ensure public key entry and generation enabled
    if userPrivKey["state"] == "normal":
        userPublicKey.config(state='normal')
    generate_pub_bttn.config(state='normal')

    # Change private key label and file name to RSA
    privKeylbl.config(text="Private Key Filename:")
    privKeyName.set("private_key.pem")
    new_keys.set("Reset Keys")


def edit_filenames():
    if v.get() != 2:
        userPublicKey.config(state="normal")
    userPrivKey.config(state="normal")
    userPassword.config(state="normal")
    userEncryptedName.config(state="normal")
    userDecryptedName.config(state="normal")


def save_filenames():
    userPrivKey.config(state="disabled")
    userPassword.config(state="disabled")
    userPublicKey.config(state="disabled")
    userEncryptedName.config(state="disabled")
    userDecryptedName.config(state="disabled")


def delete_user_files():
    directory = '.'
    for filename in os.listdir(directory):
        f = os.path.join(directory, filename)
        # checking if it is a file
        if os.path.isfile(f) and f != ".\.gitignore" and f != ".\main.py":
            os.remove(f)


def open_current_dir():
    os.system("start .")


def on_closing():
    root.update()
    if messagebox.askokcancel("Quit", "Do you want to quit? All files and keys will be deleted if program exited..."):
        root.destroy()
        delete_user_files()


root = Tk()
root.title("Encryption Program")
root.geometry("400x480")
frm = ttk.Frame(root, padding=10)

Label(root, text="Enter the message you would like to encode:").place(x=80, y=10)
messageTxt = Text(root, height=9, width=40)
messageTxt.place(x=35, y=40)

v = IntVar()
v.set(1)

Label(root,
      text="""Choose an encryption:""",
      padx=20).place(x=215, y=200)

Radiobutton(root,
            text="RSA",
            padx=20,
            variable=v,
            value=1,
            command=rsa_selected).place(x=210, y=220)

Radiobutton(root,
            text="Fernet",
            padx=20,
            variable=v,
            value=2,
            command=fernet_selected).place(x=280, y=220)

Radiobutton(root,
            text="Fernet with pwd",
            padx=20,
            variable=v,
            value=3,
            command=fernet_selected).place(x=210, y=240)

menubar = Menu(root)
filemenu = Menu(menubar, tearoff=0)
filemenu.add_command(label="Open Current Directory", command=open_current_dir)
filemenu.add_command(label="Delete Keys and Files", command=edit_filenames)
menubar.add_cascade(label="File", menu=filemenu)

editmenu = Menu(menubar, tearoff=0)
editmenu.add_command(label="Edit Filenames", command=edit_filenames)
editmenu.add_command(label="Save Filenames", command=save_filenames)
menubar.add_cascade(label="Edit", menu=editmenu)

Label(root, text="OR Message filename:").place(x=32, y=200)
userMessageFile = Entry(root, width=20)
userMessageFile.place(x=34, y=220)

privKeylbl = Label(root, text="Private Key filename:")
privKeylbl.place(x=32, y=250)
userPrivKey = Entry(root, width=20)
privKeyName = StringVar()
privKeyName.set("private_key.pem")
userPrivKey.config(textvariable=privKeyName)
userPrivKey.place(x=34, y=270)

Label(root, text="Private Key password:").place(x=32, y=300)
userPassword = Entry(root, width=20)
userPassword.insert(0, get_pwd().decode('utf-8'))
userPassword.place(x=34, y=320)

Label(root, text="Public Key filename:").place(x=250, y=300)
userPublicKey = Entry(root, width=20)
userPublicKey.insert(0, "public_key.pem")
userPublicKey.place(x=235, y=320)

Label(root, text="Encrypted msg filename:").place(x=32, y=350)
userEncryptedName = Entry(root, width=20)
userEncryptedName.insert(0, "text.encrypted")
userEncryptedName.place(x=34, y=370)

Label(root, text="Decrypted msg filename:").place(x=225, y=350)
userDecryptedName = Entry(root, width=20)
userDecryptedName.insert(0, "message.txt")
userDecryptedName.place(x=235, y=370)

generate_pub_bttn = ttk.Button(root, text="Gen Pub. Key", command=lambda: generate_pub_key())
generate_pub_bttn.place(x=205, y=400)


reset_keys_bttn = ttk.Button(root, command=lambda: reset_keys())
new_keys = StringVar()
new_keys.set("Reset Keys")
reset_keys_bttn.config(textvariable=new_keys)
reset_keys_bttn.place(x=285, y=400)

encrypt_bttn = ttk.Button(root, text="Encrypt",
                          command=lambda: encrypt_message())
encrypt_bttn.place(x=34, y=400)

decrypt_bttn = ttk.Button(root, text="Decrypt", command=lambda: decrypt_message())
decrypt_bttn.place(x=110, y=400)

root.protocol("WM_DELETE_WINDOW", on_closing)

root.config(menu=menubar)

delete_user_files()
save_filenames()
reset_keys()

root.mainloop()
