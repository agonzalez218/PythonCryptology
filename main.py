from tkinter import messagebox
from tkinter import *
from tkinter import ttk

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


def reset_keys():
    if v.get() == 2:
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

    with open('private_key.pem', 'wb') as f:
        f.write(priv_pem)

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('public_key.pem', 'wb') as f:
        f.write(pub_pem)

    messagebox.showinfo("Reset Successful!", "The public and private keys have been reset!")


def get_pwd():
    if len(userPassword.get()) > 0:
        return bytes(userPassword.get(), 'utf-8')
    return b'Wy5nDTbo5D12MYe6Hwwa'


def get_priv_key():
    if len(userPrivKey.get()) > 0:
        try:
            with open(userPrivKey.get().replace('\n', ''), "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=get_pwd(),
                    backend=default_backend()
                )
            return private_key
        except FileNotFoundError:
            return -1
    try:
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=get_pwd(),
                backend=default_backend()
            )
        return private_key
    except FileNotFoundError:
        return -1
    except ValueError:
        messagebox.showerror("Private Key Error",
                             "Ensure correct password for private key is used...")


def get_pub_key():
    if len(userPublicKey.get()) > 0:
        try:
            with open(userPublicKey.get().replace('\n', ''), "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            return public_key
        except FileNotFoundError:
            return -1
    try:
        with open("public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key
    except FileNotFoundError:
        return -1


def get_message():
    if len(userMessage.get("1.0", END)) != 1:
        f = open(userMessage.get("1.0", END).replace("\n", ""), 'rb')
        message = f.read()
        f.close()
        return message
    else:
        return bytes(messageTxt.get("1.0", END), 'utf-8')


def generate_pub_key(private_key):
    if get_priv_key() == -1:
        no_priv_key()
        return
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('public_key.pem', 'wb') as f:
        f.write(pub_pem)


def encrypt_message(message):
    if v.get() == 2:
        if len(userPrivKey.get()) > 0:
            try:
                file = open(userPrivKey.get().replace('\n', ''), 'rb')
                key = file.read()
                file.close()
            except FileNotFoundError:
                messagebox.showerror("Missing Private Key",
                                     "WARNING: Without private key, previous encrypted messages will not "
                                     "be able to be decrypted...")
                return
        else:
            try:
                file = open("fernet.key", 'rb')
                key = file.read()
                file.close()
            except FileNotFoundError:
                messagebox.showerror("Missing Private Key",
                                     "WARNING: Without private key, previous encrypted messages will not "
                                     "be able to be decrypted...")
                return
        encrypt_fern_key(key, get_message())
        return
    try:
        if get_pub_key() == -1:
            no_pub_key()
            return

        public_key = get_pub_key()

        encrypted = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        if len(userEncryptedName.get()) > 0:
            with open(userEncryptedName.get().replace('\n', ''), 'wb') as f:
                f.write(encrypted)
            messagebox.showinfo("Encryption Successful!",
                                "The message has been encrypted and placed in " + userEncryptedName.get() + " file!")
        else:
            with open("text.encrypted", 'wb') as f:
                f.write(encrypted)
            messagebox.showinfo("Encryption Successful!",
                                "The message has been encrypted and placed in text.encrypted file!")
    except ValueError:
        messagebox.showerror("Encryption Error",
                             "Encryption of selected file FAILED, please ensure you are using correct keys and "
                             "message filename...")


def decrypt_message(private_key):
    if v.get() == 2:
        if len(userPrivKey.get()) > 0:
            try:
                file = open(userPrivKey.get().replace('\n', ''), 'rb')
                key = file.read()
                file.close()
            except FileNotFoundError:
                messagebox.showerror("Missing Private Key",
                                     "WARNING: Without private key, previous encrypted messages will not "
                                     "be able to be decrypted...")
                return
        else:
            try:
                file = open("fernet.key", 'rb')
                key = file.read()
                file.close()
            except FileNotFoundError:
                messagebox.showerror("Missing Private Key",
                                     "WARNING: Without private key, previous encrypted messages will not "
                                     "be able to be decrypted...")
                return
        decrypt_fern_key(key)
        return
    try:
        if get_priv_key() == -1:
            no_priv_key()
            return

        if len(userEncryptedName.get()) > 0:
            f = open(userEncryptedName.get().replace('\n', ''), 'rb')
        else:
            f = open('text.encrypted', 'rb')

        encrypted = f.read()
        f.close()
        original_message = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        if len(userDecryptedName.get()) > 0:
            with open(userDecryptedName.get().replace('\n', ''), 'wb') as f:
                f.write(original_message)
            messagebox.showinfo("Decryption Successful!",
                                "The message has been decrypted and placed in " + userDecryptedName.get() + " file!")
        else:
            with open('message.txt', 'wb') as f:
                f.write(original_message)
            messagebox.showinfo("Decryption Successful!",
                                "The message has been encrypted and placed in message.txt file!")
    except ValueError:
        messagebox.showerror("Decryption Error",
                             "Decryption of selected file FAILED, please ensure you are using correct keys...")


def no_priv_key():
    messagebox.showerror("Missing Private Key", "WARNING: Without private key, previous encrypted messages will not "
                                                "be able to be decrypted...")


def no_pub_key():
    messagebox.showwarning("Missing Public Key", "No public key provided, generate one or move to current file "
                                                 "directory...")


def generate_fern_key():
    key = Fernet.generate_key()
    with open("fernet.key", "wb") as file:
        file.write(key)


def encrypt_fern_key(key, message):
    fern = Fernet(key)
    encrypted = fern.encrypt(message)
    if len(userEncryptedName.get()) > 0:
        with open(userEncryptedName.get().replace('\n', ''), 'wb') as file:
            file.write(encrypted)
    else:
        with open("text.encrypted", 'wb') as file:
            file.write(encrypted)


def decrypt_fern_key(key):
    fern = Fernet(key)
    if len(userEncryptedName.get()) > 0:
        file = open(userEncryptedName.get().replace('\n', ''), 'rb')
        message = file.read()
        file.close()
    else:
        file = open("text.encrypted", 'rb')
        message = file.read()
        file.close()
    original_message = fern.decrypt(message)
    if len(userDecryptedName.get()) > 0:
        with open(userDecryptedName.get().replace('\n', ''), 'wb') as file:
            file.write(original_message)
    else:
        with open("message.txt", 'wb') as file:
            file.write(original_message)


def fernet_selected():
    userPublicKey.config(state='disabled')
    generate_pub_bttn.config(state='disabled')


def rsa_selected():
    userPublicKey.config(state='normal')
    generate_pub_bttn.config(state='normal')


root = Tk()
root.title("Encryption Program")
root.geometry("400x480")
frm = ttk.Frame(root, padding=10)
Label(root, text="Enter the message you would like to encode:").place(x=80, y=10)
messageTxt = Text(root, height=9, width=40)
messageTxt.place(x=35, y=40)

Label(root, text="OR Message filename:").place(x=32, y=200)
userMessage = Text(root, height=1, width=15)
userMessage.place(x=34, y=220)

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

Label(root, text="Private Key filename:").place(x=32, y=250)
userPrivKey = Entry(root, width=20)
userPrivKey.place(x=34, y=270)

Label(root, text="Private Key password:").place(x=32, y=300)
userPassword = Entry(root, width=20)
userPassword.place(x=34, y=320)

Label(root, text="Public Key filename:").place(x=250, y=300)
userPublicKey = Entry(root, width=20)
userPublicKey.place(x=235, y=320)

Label(root, text="Encrypted msg filename:").place(x=32, y=350)
userEncryptedName = Entry(root, width=20)
userEncryptedName.place(x=34, y=370)

Label(root, text="Decrypted msg filename:").place(x=225, y=350)
userDecryptedName = Entry(root, width=20)
userDecryptedName.place(x=235, y=370)

generate_pub_bttn = ttk.Button(root, text="Gen Pub. Key", command=lambda: generate_pub_key(get_priv_key()))
generate_pub_bttn.place(x=205, y=400)

reset_keys_bttn = ttk.Button(root, text="Reset Key(s)", command=lambda: reset_keys())
reset_keys_bttn.place(x=285, y=400)

encrypt_bttn = ttk.Button(root, text="Encrypt",
                          command=lambda: encrypt_message(get_message()))
encrypt_bttn.place(x=34, y=400)

decrypt_bttn = ttk.Button(root, text="Decrypt", command=lambda: decrypt_message(get_priv_key()))
decrypt_bttn.place(x=110, y=400)

root.mainloop()
