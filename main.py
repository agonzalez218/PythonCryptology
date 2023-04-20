from functions.fernet_functions import *
from functions.rsa_functions import *


def reset_keys():
    # Generate Fernet key if using Fernet
    if v.get() == 2 or v.get() == 3:
        generate_fern_key(root, v, get_pwd(), userPrivKey.get())
        return

    # Generate RSA keys if using RSA
    if v.get() == 1:
        generate_rsa_key_pair(root, get_pwd(), userPrivKey.get(), userPublicKey.get())
        return


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


def encrypt_message():
    # Get message, if none found return error
    message = get_message()
    if message == -1:
        return -1

    # If Fernet selected:
    if v.get() == 2 or v.get() == 3:
        key = get_fernet_key(root, userPrivKey.get())
        if key == -1:
            return
        encrypt_fernet(root, userPrivKey.get(), userEncryptedName.get(), get_message())
        return

    # If RSA selected:
    if v.get() == 1:
        encrypt_rsa(root, get_pub_key(root, userPublicKey.get()), get_message(), userEncryptedName.get())


def decrypt_message():
    # If Fernet selected:
    if v.get() == 2 or v.get() == 3:
        key = get_fernet_key(root, userPrivKey.get())
        if key == -1:
            return
        decrypt_fernet(root, userPrivKey.get(), userEncryptedName.get(), userDecryptedName.get())
        return

    # If RSA selected:
    if v.get() == 1:
        decrypt_rsa(root, get_priv_key(), userEncryptedName.get(), userDecryptedName.get())


def fernet_selected():
    # Disable public key entry and generation
    if userPrivKey["state"] == "normal":
        userPublicKey.config(state='disabled')
    generate_pub_bttn.config(state='disabled')

    # Change private key label and file name to Fernet
    privKeylbl.config(text="Fernet Key Filename:")
    privKeyName.set("fernet.key")
    new_keys.set("Gen Fernet Key")
    curr_encryption.set("Fernet")
    v.set(2)


def priv_fernet_selected():
    # Disable public key entry and generation
    if userPrivKey["state"] == "normal":
        userPublicKey.config(state='disabled')
    generate_pub_bttn.config(state='disabled')

    # Change private key label and file name to Fernet
    privKeylbl.config(text="Fernet Key Filename:")
    privKeyName.set("priv_fernet.key")
    new_keys.set("Gen Fernet Key")
    curr_encryption.set("Fernet with password")
    v.set(3)


def rsa_selected():
    # Ensure public key entry and generation enabled
    if userPrivKey["state"] == "normal":
        userPublicKey.config(state='normal')
    generate_pub_bttn.config(state='normal')

    # Change private key label and file name to RSA
    privKeylbl.config(text="Private Key Filename:")
    privKeyName.set("private_key.pem")
    new_keys.set("Reset Keys")
    curr_encryption.set("RSA")
    v.set(1)


def aesgcm_selected():
    # Ensure public key entry and generation enabled
    if userPrivKey["state"] == "normal":
        userPublicKey.config(state='disabled')
    generate_pub_bttn.config(state='normal')

    # Change private key label and file name to RSA
    privKeylbl.config(text="Private Key Filename:")
    privKeyName.set("private_key.pem")
    new_keys.set("Reset Keys")
    curr_encryption.set("aesgcm")
    v.set(4)


def aesccm_selected():
    # Ensure public key entry and generation enabled
    if userPrivKey["state"] == "normal":
        userPublicKey.config(state='disabled')
    generate_pub_bttn.config(state='normal')

    # Change private key label and file name to RSA
    privKeylbl.config(text="Private Key Filename:")
    privKeyName.set("private_key.pem")
    new_keys.set("Reset Keys")
    curr_encryption.set("aesccm")
    v.set(5)


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
        if os.path.isfile(f) and not f.endswith(".gitignore") and not f.endswith(".py"):
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

menubar = Menu(root)
filemenu = Menu(menubar, tearoff=0)
filemenu.add_command(label="Open Current Directory", command=open_current_dir)
filemenu.add_command(label="Delete Keys and Files", command=edit_filenames)
menubar.add_cascade(label="File", menu=filemenu)

editmenu = Menu(menubar, tearoff=0)
editmenu.add_command(label="Edit Filenames", command=edit_filenames)
editmenu.add_command(label="Save Filenames", command=save_filenames)
menubar.add_cascade(label="Edit", menu=editmenu)

asymmetricMenu = Menu(root, tearoff=False)
asymmetricMenu.add_command(label="RSA", command=rsa_selected)

authenticatedMenu = Menu(root, tearoff=False)
authenticatedMenu.add_command(label="AESGCM")
asymmetricMenu.add_command(label="AESCCM")

key_derivation_menu = Menu(root, tearoff=False)
key_derivation_menu.add_command(label="HKDF")
key_derivation_menu.add_command(label="HMAC")
key_derivation_menu.add_command(label="PBKDF2HMAC")

symmetricMenu = Menu(root, tearoff=False)
symmetricMenu.add_command(label="AES")
symmetricMenu.add_command(label="CBC")
symmetricMenu.add_command(label="Fernet", command=fernet_selected)
symmetricMenu.add_command(label="Fernet with password", command=priv_fernet_selected)

encryptionMenu = Menu(menubar, tearoff=0)
encryptionMenu.add_cascade(label="Asymmetric", menu=asymmetricMenu)
encryptionMenu.add_cascade(label="Authenticated", menu=authenticatedMenu)
encryptionMenu.add_cascade(label="Key Derivation", menu=key_derivation_menu)
encryptionMenu.add_cascade(label="Symmetric", menu=symmetricMenu)
menubar.add_cascade(label="Encryption(s)", menu=encryptionMenu)

Label(root, text="Current Encryption:").place(x=150, y=200)
curr_encryption = StringVar()
currentEncryption = Entry(root, width=20, textvariable=curr_encryption, state="disabled")
curr_encryption.set("RSA")
currentEncryption.place(x=150, y=220)

Label(root, text="OR Message filename:").place(x=32, y=250)
userMessageFile = Entry(root, width=20)
userMessageFile.place(x=34, y=270)

Label(root, text="Public Key filename:").place(x=250, y=250)
userPublicKey = Entry(root, width=20)
userPublicKey.insert(0, "public_key.pem")
userPublicKey.place(x=235, y=270)

privKeylbl = Label(root, text="Private Key filename:")
privKeylbl.place(x=32, y=300)
userPrivKey = Entry(root, width=20)
privKeyName = StringVar()
privKeyName.set("private_key.pem")
userPrivKey.config(textvariable=privKeyName)
userPrivKey.place(x=34, y=320)

Label(root, text="Private Key password:").place(x=250, y=300)
userPassword = Entry(root, width=20)
userPassword.insert(0, get_pwd().decode('utf-8'))
userPassword.place(x=235, y=320)

Label(root, text="Encrypted msg filename:").place(x=32, y=350)
userEncryptedName = Entry(root, width=20)
userEncryptedName.insert(0, "text.encrypted")
userEncryptedName.place(x=34, y=370)

Label(root, text="Decrypted msg filename:").place(x=225, y=350)
userDecryptedName = Entry(root, width=20)
userDecryptedName.insert(0, "message.txt")
userDecryptedName.place(x=235, y=370)

generate_pub_bttn = ttk.Button(root, text="Gen Pub. Key",
                               command=lambda: generate_pub_key(root, get_priv_key(), userPublicKey.get()))
generate_pub_bttn.place(x=205, y=420)

reset_keys_bttn = ttk.Button(root, command=lambda: reset_keys())
new_keys = StringVar()
new_keys.set("Reset Keys")
reset_keys_bttn.config(textvariable=new_keys)
reset_keys_bttn.place(x=285, y=420)

encrypt_bttn = ttk.Button(root, text="Encrypt",
                          command=lambda: encrypt_message())
encrypt_bttn.place(x=34, y=420)

decrypt_bttn = ttk.Button(root, text="Decrypt", command=lambda: decrypt_message())
decrypt_bttn.place(x=110, y=420)

root.protocol("WM_DELETE_WINDOW", on_closing)

root.config(menu=menubar)

delete_user_files()
save_filenames()
reset_keys()

root.mainloop()
