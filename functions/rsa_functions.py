from functions.imports import *


# Generate new RSA key pair and place into files
def generate_rsa_key_pair(root, password, priv_key_filename, pub_key_filename):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )

    # Enter private and public key generated into files
    try:
        with open(priv_key_filename, 'wb') as f:
            f.write(priv_pem)

        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(pub_key_filename, 'wb') as f:
            f.write(pub_pem)
    except FileNotFoundError:
        messagebox.showerror("File Not Found",
                             "ERROR: Filename not found in current directory...")
        return -1

    root.update()
    messagebox.showinfo("Reset Successful!", "The public and private keys have been reset!")
    return 1


# Decrypt RSA then write decrypted message to file
def decrypt_rsa(root, private_key, encrypted_name, decrypted_name):
    # If private key not found, return error
    try:
        if private_key == -1:
            return -1

        # Get encrypted message from user specified file
        f = open(encrypted_name, 'rb')
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
        with open(decrypted_name, 'wb') as f:
            f.write(original_message)

        # Show Success Message
        root.update()
        messagebox.showinfo("Decryption Successful!",
                            "The message has been decrypted and placed in " + decrypted_name + " file!")
        return 1
        # If user specified file not in current directory, return error
    except FileNotFoundError:
        root.update()
        messagebox.showerror("File Not Found",
                             "ERROR: Encrypted and/or Decrypted Filename not found in current directory...")
        return -1

    # If decryption failed, return error
    except ValueError:
        root.update()
        messagebox.showerror("Decryption Error",
                             "Decryption of selected file FAILED, please ensure you are using correct keys...")
        return -1


# Encrypt message with RSA then write encrypted message to file
def encrypt_rsa(root, public_key, message, encrypted_name):
    try:
        if public_key == -1:
            return -1

        encrypted = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))

        # Enter encrypted message into user specified file
        with open(encrypted_name, 'wb') as f:
            f.write(encrypted)
        root.update()
        messagebox.showinfo("Encryption Successful!",
                            "The message has been encrypted and placed in " + encrypted_name + " file!")
        # If user specified file not in current directory, return error
    except FileNotFoundError:
        root.update()
        messagebox.showerror("File Not Found",
                             "ERROR: Encrypted Filename not found in current directory...")
        return -1
        # If encryption failed, return error
    except ValueError:
        root.update()
        messagebox.showerror("Encryption Error",
                             "Encryption of selected file FAILED, please ensure you are using correct keys and "
                             "message filename...")
        return -1


# Generate new RSA public key and place into file
def generate_rsa_pub_key(root, priv_key, pub_key_filename):
    # Get private key, if not found return error
    if priv_key == -1:
        return -1

    public_key = priv_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # If user specified filename, use that, otherwise return error
    if len(pub_key_filename) > 0:
        with open(pub_key_filename, 'wb') as f:
            f.write(pub_pem)
    else:
        root.update()
        messagebox.showerror("Public Key Error",
                             "ERROR: Public Key name not specified...")
        return -1


# Returns RSA public key from file
def get_rsa_pub_key(root, pub_key_filename):
    # If user did not specify public key filename return error
    if len(pub_key_filename) < 1:
        root.update()
        messagebox.showerror("Public Key Error",
                             "ERROR: Public Key name not specified...")
        return -1
    try:
        # Get public key from file
        with open(pub_key_filename, "rb") as key_file:
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


# Returns RSA private key from file
def get_rsa_priv_key(root, priv_key_filename, password):
    # If user did not specify private key filename return error
    if len(priv_key_filename) < 1:
        root.update()
        messagebox.showerror("Private Key Error",
                             "ERROR: Private Key name not specified...")
    try:
        # Get private key from file
        with open(priv_key_filename, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
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
