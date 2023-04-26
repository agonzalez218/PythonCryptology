

from functions.imports import *


# Generates an AES key and AES IV and places in appropriate files
def generate_aes_keys(root, priv_key_filename, pub_key_filename):
    key = os.urandom(32)
    iv = os.urandom(16)
    try:
        with open(priv_key_filename, "wb") as file:
            file.write(key)

        with open(pub_key_filename, "wb") as file:
            file.write(iv)
    except FileNotFoundError:
        root.update()
        messagebox.showerror("AES Keys Reset Error",
                             "Key or IV filename not found..")
        return -1
    root.update()
    messagebox.showinfo("AES Keys Reset Success",
                        "AES Key and IV have been reset and are in " + priv_key_filename + " and " + pub_key_filename)


# Generates AESGCM key and places in file
def generate_aesgcm(root, priv_key_filename):
    key = AESGCM.generate_key(bit_length=128)
    try:
        with open(priv_key_filename, "wb") as file:
            file.write(key)
    except FileNotFoundError:
        root.update()
        messagebox.showerror("AESGCM Keys Reset Error",
                             "Key filename not found..")
        return -1
    root.update()
    messagebox.showinfo("AESGCM Key Reset Success",
                        "AESGCM Key has been reset and placed in " + priv_key_filename)


# Generates AESCCM key and places in file
def generate_aesccm(root, priv_key_filename):
    key = AESCCM.generate_key(bit_length=128)
    try:
        with open(priv_key_filename, "wb") as file:
            file.write(key)
    except FileNotFoundError:
        root.update()
        messagebox.showerror("AESCCM Keys Reset Error",
                             "Key filename not found..")
        return -1
    root.update()
    messagebox.showinfo("AESCCM Key Reset Success",
                        "AESCCM Key has been reset and placed in " + priv_key_filename)


# Generates a new AES IV
def generate_aes_iv(root, pub_key_filename):
    iv = os.urandom(16)
    try:
        with open(pub_key_filename, "wb") as file:
            file.write(iv)
    except FileNotFoundError:
        root.update()
        messagebox.showerror("AES Keys Reset Error",
                             "IV filename not found..")
        return -1
    root.update()
    messagebox.showinfo("AES Keys Reset Success",
                        "AES IV has been reset and placed in " + pub_key_filename)


# Returns AES IV from file
def get_aes_iv(root, pub_key_filename):
    try:
        file = open(pub_key_filename, 'rb')
        iv = file.read()
        file.close()
    except FileNotFoundError:
        root.update()
        messagebox.showerror("AES IV Error",
                             "IV filename not found..")
        return -1
    return iv


# Returns AES key from file
def get_aes_key(root, priv_key_filename):
    try:
        file = open(priv_key_filename, 'rb')
        key = file.read()
        file.close()
    except FileNotFoundError:
        root.update()
        messagebox.showerror("AES Keys Error",
                             "Key filename not found..")
        return -1
    return key


# Returns AESGCM key from file
def get_aesgcm_key(root, priv_key_filename):
    try:
        file = open(priv_key_filename, 'rb')
        key = file.read()
        file.close()
    except FileNotFoundError:
        root.update()
        messagebox.showerror("AESGCM Keys Error",
                             "Key filename not found..")
        return -1
    return key


# Returns AESCCM key from file
def get_aesccm_key(root, priv_key_filename):
    try:
        file = open(priv_key_filename, 'rb')
        key = file.read()
        file.close()
    except FileNotFoundError:
        root.update()
        messagebox.showerror("AESCCM Keys Error",
                             "Key filename not found..")
        return -1
    return key


# Encrypt message with AES method
# Requires 16 block size increments, so add padding
# Add size of padding to end of file
def encrypt_aes(root, key, iv, message, encrypted_filename):
    if key == -1 or iv == -1:
        return -1

    add_bit_len = 16 - (len(message) % 16)

    message += bytes(''.join(
        random.SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in
        range(add_bit_len)), 'utf-8')

    digits = 2
    if add_bit_len < 10:
        digits = 1

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(message) + encryptor.finalize()
    try:
        with open(encrypted_filename, "wb") as file:
            file.write(bytes(str(digits), "utf-8") + bytes(str(add_bit_len), "utf-8") + encrypted)
    except FileNotFoundError:
        root.update()
        messagebox.showerror("AES Encryption Error",
                             "Encrypted Message Filename not found..")
        return -1
    root.update()
    messagebox.showinfo("AES Encryption Success",
                        "Encrypted message placed in " + encrypted_filename)


# Encrypt message with AESGCM method
# Requires randomization or nonce with encryption
# Add nonce size and nonce to beginning of file
def encrypt_aesgcm(root, key, message, encrypted_filename, password):
    if key == -1:
        return -1
    aesgcm = AESGCM(key)
    nonce_size = 12
    nonce = os.urandom(12)
    aad = password
    encrypted = aesgcm.encrypt(nonce, message, aad)
    try:
        with open(encrypted_filename, "wb") as file:
            file.write(bytes(str(nonce_size), "utf-8") + nonce + encrypted)
    except FileNotFoundError:
        root.update()
        messagebox.showerror("AESGCM Encryption Error",
                             "Encrypted Message Filename not found..")
        return -1
    root.update()
    messagebox.showinfo("AESGCM Encryption Success",
                        "Encrypted message placed in " + encrypted_filename)


# Encrypt message with AESCCM method
# Requires randomization or nonce with encryption
# Add nonce size and nonce to beginning of file
def encrypt_aesccm(root, key, message, encrypted_filename, password):
    if key == -1:
        return -1
    aesccm = AESCCM(key)
    nonce_size = 13
    nonce = os.urandom(13)
    aad = password
    encrypted = aesccm.encrypt(nonce, message, aad)
    try:
        with open(encrypted_filename, "wb") as file:
            file.write(bytes(str(nonce_size), "utf-8") + nonce + encrypted)
    except FileNotFoundError:
        root.update()
        messagebox.showerror("AESCCM Encryption Error",
                             "Encrypted Message Filename not found..")
        return -1
    root.update()
    messagebox.showinfo("AESCCM Encryption Success",
                        "Encrypted message placed in " + encrypted_filename)


# Decrypt message with AES method
# Get size of padding, decode into digit
# Only write message to file not randomized data
def decrypt_aes(root, key, iv, encrypted_filename, decrypted_filename):
    if key == -1 or iv == -1:
        return -1

    try:
        file = open(encrypted_filename, 'rb')
        encrypted = file.read()
        file.close()
    except FileNotFoundError:
        root.update()
        messagebox.showerror("AES Decryption Error",
                             "Encrypted Message Filename not found..")
        return -1

    digits = 0
    if encrypted[0] == 50:
        digits = encrypted[1:3]
        digits = digits.decode("utf-8")

        encrypted = encrypted[3:]
    elif encrypted[0] == 49:
        digits = encrypted[1:2]
        digits = digits.decode("utf-8")

        encrypted = encrypted[2:]

    try:
        cipher = Cipher(algorithm=AES(key), mode=CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
        decrypted.decode("utf-8")
    except ValueError:
        root.update()
        messagebox.showerror("AES Decryption Error",
                             "Unable to decrypt message...")
        return -1
    if decrypted == b"":
        root.update()
        messagebox.showerror("AES Decryption Error",
                             "Unable to decrypt message...")
        return -1
    try:
        with open(decrypted_filename, "wb") as file:
            file.write(decrypted[:-int(digits)])
    except FileNotFoundError:
        root.update()
        messagebox.showerror("AES Decryption Error",
                             "Decrypted Message Filename not found..")
        return -1
    root.update()
    messagebox.showinfo("AES Decryption Success",
                        "Decrypted message placed in " + decrypted_filename)


# Decrypt message with AESGCM method
# Get size of nonce, decode into digit
# Retrieve nonce from beginning of file
# Only write decrypted message into file
def decrypt_aesgcm(root, key, encrypted_filename, decrypted_filename, password):
    if key == -1:
        return -1

    try:
        file = open(encrypted_filename, 'rb')
        encrypted = file.read()
        file.close()
    except FileNotFoundError:
        root.update()
        messagebox.showerror("AESGCM Decryption Error",
                             "Encrypted Message Filename not found..")
        return -1

    digits = encrypted[0:2]
    digits = digits.decode("utf-8")
    digits = int(digits)
    nonce = encrypted[2:digits+2]
    encrypted = encrypted[digits+2:]

    aesgcm = AESGCM(key)
    decrypted = aesgcm.decrypt(nonce, encrypted, password)

    try:
        with open(decrypted_filename, "wb") as file:
            file.write(decrypted)
    except FileNotFoundError:
        root.update()
        messagebox.showerror("AESGCM Decryption Error",
                             "Decrypted Message Filename not found..")
        return -1
    root.update()
    messagebox.showinfo("AESGCM Decryption Success",
                        "Decrypted message placed in " + decrypted_filename)


# Decrypt message with AESCCM method
# Get size of nonce, decode into digit
# Retrieve nonce from beginning of file
# Only write decrypted message into file
def decrypt_aesccm(root, key, encrypted_filename, decrypted_filename, password):
    if key == -1:
        return -1

    try:
        file = open(encrypted_filename, 'rb')
        encrypted = file.read()
        file.close()
    except FileNotFoundError:
        root.update()
        messagebox.showerror("AESCCM Decryption Error",
                             "Encrypted Message Filename not found..")
        return -1

    digits = encrypted[0:2]
    digits = digits.decode("utf-8")
    digits = int(digits)
    nonce = encrypted[2:digits + 2]
    encrypted = encrypted[digits + 2:]

    aesccm = AESCCM(key)
    decrypted = aesccm.decrypt(nonce, encrypted, password)

    try:
        with open(decrypted_filename, "wb") as file:
            file.write(decrypted)
    except FileNotFoundError:
        root.update()
        messagebox.showerror("AESCCM Decryption Error",
                             "Decrypted Message Filename not found..")
        return -1
    root.update()
    messagebox.showinfo("AESCCM Decryption Success",
                        "Decrypted message placed in " + decrypted_filename)
