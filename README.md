# PythonCryptology | April 2023
This project is a tool that gives a user access to multiple encryption methods. The user may enter a message, or link to a file with the message, then choose an encryption method. Once chosen, they simply set the parameters or accept the defaults and press encrypt. This will create an encrypted file from the message in the specified filename. The user may move it to another directory or decode it using the same parameters.

## Section Links
[Main Menu](#main-menu)<br/>
[Encryption Methods](#encryption-methods)<br/>
[Personalization](#personalization)<br/>


## Main Menu
This is the default Main Menu:<br/>
![MainMenu](https://github.com/agonzalez218/PythonCryptology/assets/60588691/676742c3-8230-4d47-9d33-f91df31df50b)<br/>

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
![FernetSelected](https://github.com/agonzalez218/PythonCryptology/assets/60588691/7157d5bd-42f4-43db-9584-a94f7ad51000)
<br/>

Not all encryption methods use two keys or a password. Thus, based on the method chosen, user input boxes will be shown or not.
In addition, buttons shown at the bottom will also not be visible to prevent confusion or unusable buttons.

## Error Handling
The following images are alert messages that help to guide the user through error handling<br/>
The following image shows a successful encrption:<br/>
![EncryptionSucess](https://github.com/agonzalez218/PythonCryptology/assets/60588691/c3af2d8b-b53f-4a03-b5e0-50184363bedd)
<br/>
It will show the encryption method used, and the filename where the encrypted message was placed.<br/>

The following image shows a successful decryption:<br/>
![DecryptionSucess](https://github.com/agonzalez218/PythonCryptology/assets/60588691/2df3580d-4eb3-426c-891f-b3093d531e31)
<br/>
It will show the encryption method used, and the filename where the decrypted message was placed.<br/>

There will also be alerts shown for errors that come along the way. The following list is possible errors that can occur and have alert messages to make the user aware of the failure.
- Incorrect password
- Invalid or empty filename
- Invalid or empty public key
- Invalid or empty private key
- Failed Decryption ( could be due to wrong encryption method or other reasons so is left vague )

The final alert message that will be shown is below:<br/>
![Quit](https://github.com/agonzalez218/PythonCryptology/assets/60588691/2bee9c22-83d3-429f-a966-bbf302b1078b)
<br/>
When the user exits the program, all files created by the user will be deleted. This prevents someone from re-using or accessing them in the next program usage. Deletion isn't fullproof and may be able to be recovered.


