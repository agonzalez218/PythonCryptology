# PythonCryptology | May 2023
This project is a tool that gives a user access to multiple encryption methods. The user may enter a message, or link to a file with the message, then choose an encryption method. Once chosen, they simply set the parameters or accept the defaults and press encrypt. This will create an encrypted file from the message in the specified filename. The user may move it to another directory or decode it using the same parameters.

## Section Links
[Main Menu](#main-menu)<br/>
[Encryption Methods](#encryption-methods)<br/>
[Personalization](#personalization)<br/>


## Main Menu
This is the default Main Menu:<br/>
![Menu](https://github.com/agonzalez218/PythonCryptology/assets/60588691/802fbd22-17fa-4423-8440-b9fb0f92315c)<br/>

The Menu at the top gives the following options:
- File
  - Delete Keys and Files
  - Open Current Directory
- Edit
  - Edit Filenames
  - Read Password from File
  - Save Password to File
- Encryption(s)
  - Asymmetric
    - RSA
  - Authenticated
    - AESGCM
    - AESCCM
  - Symmetric
    - AES
    - Fernet
    - Fernet with password 

The options at the bottom, below the message text box, are further explained in [Personalization](#personalization)<br/>

## Encryption Methods
- Asymmetric - different key used for encryption and decryption
    - RSA
 - Authenticated - uses same key for encryption and decryption with additional authenticated data
    - AESGCM
    - AESCCM
 - Symmetric - same key used for encryption and decryption
    - AES
    - Fernet
    - Fernet with password 

## Personalization
The following image shows how the options provided to a user change based on the encryption method selected:<br/>
![Fernet](https://github.com/agonzalez218/PythonCryptology/assets/60588691/7b5896ed-4e46-4b2c-b256-c17f50ded158)<br/>

Not all encryption methods use two keys or a password. Thus, based on the method chosen, user input boxes will be shown or not.
In addition, buttons shown at the bottom will also not be visible to prevent confusion or unusable buttons.

## Error Handling
The following images are alert messages that help to guide the user through error handling<br/>
The following image shows a successful encrption:<br/>
![image](https://github.com/agonzalez218/PythonCryptology/assets/60588691/14150486-1afa-429b-bc5d-078cc20d7592)<br/>
It will show the encryption method used, and the filename where the encrypted message was placed.<br/>

The following image shows a successful decryption:<br/>
![image](https://github.com/agonzalez218/PythonCryptology/assets/60588691/2737208f-4c04-4cf3-8571-466c72142404)<br/>
It will show the encryption method used, and the filename where the decrypted message was placed.<br/>

There will also be alerts shown for errors that come along the way. The following list is possible errors that can occur and have alert messages to make the user aware of the failure.
- Incorrect password
- Invalid or empty filename
- Invalid or empty public key
- Invalid or empty private key
- Failed Decryption ( could be due to wrong encryption method or other reasons so is left vague )

The final alert message that will be shown is below:<br/>
![image](https://github.com/agonzalez218/PythonCryptology/assets/60588691/ca3c6955-490c-4a98-867f-253c837ddce2)<br/>
When the user exits the program, all files created by the user will be deleted. This prevents someone from re-using or accessing them in the next program usage. Deletion isn't fullproof and may be able to be recovered.


