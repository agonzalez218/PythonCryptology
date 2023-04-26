from functions.imports import *


# Generate fernet key and place into file
# If fernet with password, create key with password
def generate_fern_key(root, v, password, priv_key_filename):
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
        key = base64.urlsafe_b64encode(kdf.derive(password))

    # If user has not specified fernet key name, return error
    if len(priv_key_filename) < 1 or key == -1:
        root.update()
        messagebox.showerror("Fernet Key Error",
                             "Fernet key filename not specified..")
        return -1

    # Enter fernet key into user specified file
    with open(priv_key_filename, "wb") as file:
        file.write(key)
    messagebox.showinfo("Fernet Key Success",
                        "Fernet Key was generated and placed in " + priv_key_filename)


# Encrypt message with Fernet then place encrypted message in file
def encrypt_fernet(root, priv_key_filename, encrypted_name, message):
    fern = Fernet(get_fernet_key(root, priv_key_filename))
    encrypted = fern.encrypt(message)

    # If user has not specified encrypted name, return error
    if len(encrypted_name) < 1:
        root.update()
        messagebox.showerror("Fernet Encryption",
                             "Fernet encrypted message filename not specified..")
        return -1

    # Enter encrypted message into user specified file
    with open(encrypted_name, 'wb') as file:
        file.write(encrypted)

    # Show Success Message
    root.update()
    messagebox.showinfo("Encryption Successful!",
                        "The message has been encrypted and placed in " + encrypted_name + " file!")


# Decrypt message with Fernet then place decrypted message in file
def decrypt_fernet(root, priv_key_filename, encrypted_name, decrypted_name):
    fern = Fernet(get_fernet_key(root, priv_key_filename))

    # If user has not specified encrypted name, return error
    if len(encrypted_name) < 1:
        root.update()
        messagebox.showerror("Fernet Encryption",
                             "Fernet encrypted message filename not specified..")
        return -1

    # If user has specified encrypted name, attempt to get encrypted message
    # If file name not found, return error
    try:
        file = open(encrypted_name, 'rb')
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
        if len(decrypted_name) < 1:
            root.update()
            messagebox.showerror("Fernet Decryption",
                                 "Fernet decrypted message filename not specified..")
            return -1

        # Enter message into user specified filename
        with open(decrypted_name, 'wb') as file:
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
                        "The message has been decrypted and placed in " + decrypted_name + " file!")


# Get fernet key from file
def get_fernet_key(root, priv_key_filename):
    try:
        # Get fernet key from user specified file
        file = open(priv_key_filename, 'rb')
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
