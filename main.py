from tkinter.simpledialog import askstring

from functions.fernet_functions import *
from functions.rsa_functions import *
from functions.aes_functions import *


# Generate secondary key, public or IV
def generate_secondary_key():
    # Generate new RSA pub key
    if v.get() == 1:
        generate_rsa_pub_key(root, get_rsa_priv_key(root, userPrivKey.get(), get_pwd()), userPublicKey.get())

    # Generate new AES IV
    if v.get() == 6:
        generate_aes_iv(root, userPublicKey.get())


# Reset key pairs or, if only one key needed, primary key
def reset_keys():
    # Generate RSA keys if using RSA
    if v.get() == 1:
        generate_rsa_key_pair(root, get_pwd(), userPrivKey.get(), userPublicKey.get())
        return

    # Generate Fernet key if using Fernet
    if v.get() == 2 or v.get() == 3:
        generate_fern_key(root, v, get_pwd(), userPrivKey.get())
        return

    # Generate AESGCM key if using AESGCM
    if v.get() == 4:
        generate_aesgcm(root, userPrivKey.get())

    # Generate AESCCM key if using AESCCM
    if v.get() == 5:
        generate_aesccm(root, userPrivKey.get())

    # If AES Selected:
    if v.get() == 6:
        generate_aes_keys(root, userPrivKey.get(), userPublicKey.get())


# Encrypt message based on encryption method selected
def encrypt_message():
    # Get message, if none found return error
    message = get_message()
    if message == -1:
        return -1

    # If RSA selected:
    if v.get() == 1:
        encrypt_rsa(root, get_rsa_pub_key(root, userPublicKey.get()), message, userEncryptedName.get())

    # If Fernet selected:
    if v.get() == 2 or v.get() == 3:
        key = get_fernet_key(root, userPrivKey.get())
        if key == -1:
            return
        encrypt_fernet(root, userPrivKey.get(), userEncryptedName.get(), message)
        return

    # If AESGCM selected:
    if v.get() == 4:
        encrypt_aesgcm(root, get_aesgcm_key(root, userPrivKey.get()), get_message(), userEncryptedName.get(),
                       get_pwd())

    # If AESCCM selected:
    if v.get() == 5:
        encrypt_aesccm(root, get_aesccm_key(root, userPrivKey.get()), get_message(), userEncryptedName.get(),
                       get_pwd())

    # If AES Selected:
    if v.get() == 6:
        encrypt_aes(root, get_aes_key(root, userPrivKey.get()), get_aes_iv(root, userPublicKey.get()), message,
                    userEncryptedName.get())


# Decrypt message based on encryption method selected
def decrypt_message():
    # If RSA selected:
    if v.get() == 1:
        decrypt_rsa(root, get_rsa_priv_key(root, userPrivKey.get(), get_pwd()), userEncryptedName.get(),
                    userDecryptedName.get())
        return

    # If Fernet selected:
    if v.get() == 2 or v.get() == 3:
        key = get_fernet_key(root, userPrivKey.get())
        if key == -1:
            return
        decrypt_fernet(root, userPrivKey.get(), userEncryptedName.get(), userDecryptedName.get())
        return

    # If AESGCM selected:
    if v.get() == 4:
        decrypt_aesgcm(root, get_aesgcm_key(root, userPrivKey.get()), userEncryptedName.get(), userDecryptedName.get(),
                       get_pwd())

    # If AESCCM selected:
    if v.get() == 5:
        decrypt_aesccm(root, get_aesccm_key(root, userPrivKey.get()), userEncryptedName.get(), userDecryptedName.get(),
                       get_pwd())

    # If AES Selected:
    if v.get() == 6:
        decrypt_aes(root, get_aes_key(root, userPrivKey.get()), get_aes_iv(root, userPublicKey.get()),
                    userEncryptedName.get(), userDecryptedName.get())
        return


# Get password, or aad, from textbox or generate new one
def get_pwd():
    # If user specified password, use that, otherwise generate random string
    if len(user_password_string.get()) > 0:
        return bytes(user_password_string.get(), 'utf-8')

    new_password = bytes(''.join(
        random.SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in
        range(15)), 'utf-8')

    user_password_string.set(new_password.decode("utf-8"))

    # Generate new random password if user did not specify one
    return new_password


# Save password to file
def save_pwd():
    try:
        filename = askstring('Password Filename', 'What would you like to save password as?')
        with open(filename, "wb") as file:
            file.write(bytes(userPassword.get(), "utf-8"))
    except FileNotFoundError:
        root.update()
        messagebox.showerror("Password Error",
                             "Password Filename not found..")
        return -1
    root.update()
    messagebox.showinfo("Password Saved Successfully",
                        "Password placed in " + filename)


# Get password to file
def read_pwd():
    try:
        filename = askstring('Password Filename', 'What would you like to read password from?')
        f = open(filename, 'rb')
        root.update()
        user_password_string.set(f.read().decode('utf-8'))
        f.close()
    # If filename specified by user but not found return error
    except FileNotFoundError:
        root.update()
        messagebox.showerror("Password Error",
                             "Password Filename not found..")
        return -1
    root.update()
    messagebox.showinfo("Password Read Successfully",
                        "Password retrieved from " + filename)


# Get message to be encrypted, either from text box or file
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


# Change form to match settings of selected encryption type
def encryption_selected(type_selected):
    v.set(type_selected)
    if type_selected == 1:
        # Change private key label and file name to RSA
        privKeylbl.config(text="Private Key Filename:")
        privKeyName.set("private_key.pem")
        pubKeyLbl.config(text="Public Key Filename:")
        pubKeyName.set("public_key.pem")
        gen_pub_bttn.set("Gen. Pub Key")
        new_keys.set("Reset Keys")
        curr_encryption.set("RSA")
        password_string_lbl.set("Private password:")
        v.set(1)
        show_password()
        show_pub_key()

    if type_selected == 2:
        # Change private key label and file name to Fernet
        privKeylbl.config(text="Fernet Key Filename:")
        privKeyName.set("fernet.key")
        new_keys.set("Gen Fernet Key")
        curr_encryption.set("Fernet")
        v.set(2)
        hide_pub_key()
        hide_password()

    if type_selected == 3:
        # Change private key label and file name to Fernet
        privKeylbl.config(text="Fernet Key Filename:")
        privKeyName.set("priv_fernet.key")
        new_keys.set("Gen Fernet Key")
        curr_encryption.set("Fernet with password")
        password_string_lbl.set("Private password:")
        v.set(3)
        hide_pub_key()
        show_password()

    if type_selected == 4:
        # Change private key label and file name to Fernet
        privKeylbl.config(text="AESGCM Key Filename:")
        privKeyName.set("aesgcm.key")
        new_keys.set("Gen AESGCM Key")
        curr_encryption.set("AESGCM")
        password_string_lbl.set("Password or AAD:")
        v.set(4)
        hide_pub_key()
        show_password()

    if type_selected == 5:
        # Change private key label and file name to Fernet
        privKeylbl.config(text="AESCCM Key Filename:")
        privKeyName.set("aesccm.key")
        new_keys.set("Gen AESCCM Key")
        curr_encryption.set("AESCCM")
        password_string_lbl.set("Password or AAD:")
        v.set(5)
        hide_pub_key()
        show_password()

    if type_selected == 6:
        # Change private key label and file name to Fernet
        privKeylbl.config(text="AES Key Filename:")
        privKeyName.set("aes.key")
        pubKeyLbl.config(text="AES IV Filename:")
        pubKeyName.set("iv.aes")
        gen_pub_bttn.set("Gen. New IV")
        new_keys.set("Reset Keys")
        curr_encryption.set("AES")
        password_string_lbl.set("Private password:")
        v.set(6)
        show_password()
        show_pub_key()

    if not os.path.isfile(userPrivKey.get()):
        reset_keys()
    save_filenames()


# Enable entry of all text boxes
def edit_filenames():
    if v.get() != 2:
        userPublicKey.config(state="normal")
    userPrivKey.config(state="normal")
    userPassword.config(state="normal")
    userEncryptedName.config(state="normal")
    userDecryptedName.config(state="normal")


# Disable entry of all text boxes
def save_filenames():
    userPrivKey.config(state="disabled")
    userPassword.config(state="disabled")
    userPublicKey.config(state="disabled")
    userEncryptedName.config(state="disabled")
    userDecryptedName.config(state="disabled")


# Delete all user files such as keys and data
def delete_user_files():
    if messagebox.askokcancel("Quit", "Do you want to quit? All files and keys will be deleted if program exited..."):
        directory = '.'
        for filename in os.listdir(directory):
            f = os.path.join(directory, filename)
            # checking if it is a file
            if os.path.isfile(f) and not f.endswith(".gitignore") and not f.endswith(".py"):
                os.remove(f)
        return 1


# Show user current directory
def open_current_dir():
    os.system("start .")


# When application closed, show warning that all user files will be deleted
def on_closing():
    root.update()

    result = delete_user_files()
    if result == 1:
        root.destroy()


# Disable password entry
def hide_password():
    root.update()
    passwordLbl.place_forget()
    userPassword.place_forget()


# Disable public key entry and generation
def hide_pub_key():
    root.update()
    pubKeyLbl.place_forget()
    userPublicKey.place_forget()
    generate_pub_bttn.place_forget()


# Re-enable password entry
def show_password():
    root.update()
    passwordLbl.place(x=265, y=300)
    userPassword.place(x=235, y=320)


# Re-enable public key entry and generation
def show_pub_key():
    root.update()
    pubKeyLbl.place(x=250, y=250)
    userPublicKey.place(x=235, y=270)
    generate_pub_bttn.place(x=205, y=420)


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
filemenu.add_command(label="Delete Keys and Files", command=delete_user_files)
filemenu.add_command(label="Open Current Directory", command=open_current_dir)
menubar.add_cascade(label="File", menu=filemenu)

editmenu = Menu(menubar, tearoff=0)
editmenu.add_command(label="Edit Filenames", command=edit_filenames)
editmenu.add_command(label="Read Password from File", command=read_pwd)
editmenu.add_command(label="Save Password to File", command=save_pwd)
menubar.add_cascade(label="Edit", menu=editmenu)

asymmetricMenu = Menu(root, tearoff=False)
asymmetricMenu.add_command(label="RSA", command=lambda: encryption_selected(1))

authenticatedMenu = Menu(root, tearoff=False)
authenticatedMenu.add_command(label="AESGCM", command=lambda: encryption_selected(4))
authenticatedMenu.add_command(label="AESCCM", command=lambda: encryption_selected(5))

symmetricMenu = Menu(root, tearoff=False)
symmetricMenu.add_command(label="AES", command=lambda: encryption_selected(6))
symmetricMenu.add_command(label="Fernet", command=lambda: encryption_selected(2))
symmetricMenu.add_command(label="Fernet with password", command=lambda: encryption_selected(3))

encryptionMenu = Menu(menubar, tearoff=0)
encryptionMenu.add_cascade(label="Asymmetric", menu=asymmetricMenu)
encryptionMenu.add_cascade(label="Authenticated", menu=authenticatedMenu)
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

pubKeyLbl = Label(root, text="Public Key filename:")
pubKeyLbl.place(x=250, y=250)

userPublicKey = Entry(root, width=20)
pubKeyName = StringVar()
pubKeyName.set("public_key.pem")
userPublicKey.config(textvariable=pubKeyName)
userPublicKey.place(x=235, y=270)

privKeylbl = Label(root, text="Private Key filename:")
privKeylbl.place(x=32, y=300)
userPrivKey = Entry(root, width=20)
privKeyName = StringVar()
privKeyName.set("private_key.pem")
userPrivKey.config(textvariable=privKeyName)
userPrivKey.place(x=34, y=320)

password_string_lbl = StringVar()
password_string_lbl.set("Private password:")
passwordLbl = Label(root, textvariable=password_string_lbl)

passwordLbl.place(x=265, y=300)
user_password_string = StringVar()
user_password_string.set(get_pwd().decode('utf-8'))
userPassword = Entry(root, width=20, textvariable=user_password_string)
userPassword.place(x=235, y=320)

Label(root, text="Encrypted msg filename:").place(x=32, y=350)
userEncryptedName = Entry(root, width=20)
userEncryptedName.insert(0, "text.encrypted")
userEncryptedName.place(x=34, y=370)

Label(root, text="Decrypted msg filename:").place(x=225, y=350)
userDecryptedName = Entry(root, width=20)
userDecryptedName.insert(0, "message.txt")
userDecryptedName.place(x=235, y=370)

gen_pub_bttn = StringVar()
gen_pub_bttn.set("Gen Pub. Key")
generate_pub_bttn = ttk.Button(root, textvariable=gen_pub_bttn,
                               command=lambda: generate_secondary_key())
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

save_filenames()
reset_keys()

root.mainloop()
