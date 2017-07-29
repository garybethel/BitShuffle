## BitShuffle


![Alt text](/BitShuffle.jpg?raw=true "BitShuffle")


#### What it is
BitShuffle is a file encryption program. It uses a 256 bit key with Rijndael 256 bit blocksize and a cbc cipher to encrypt files.


#### How it works

The user supplies a passphrase that creates a 256 bit key. That is used to encrypt an iv and a 256 bit *key that was created using a randomly generated passhprase. 
This randomly created key and iv are used to encrypt the message.
The salt and iv used to encrypt the message iv and key is saved in the file header.
The encrypted message iv and key is then also embedded into the file header.
*The message key itself is created using a 40 character passphrase that is randomly generated.

The idea behind doing things like this is that if the user wanted to change the passphrase then they only needed to generate a new key and encrypt the message iv and key 
instead of the entire message itself. There are also other instances where handling the encryption like this may be useful

#### Usage

**Visual Studio C# Project**
Simply open the Visual Studio WPF project. Bouncy Castle cryptography library was used only in the HMAC generation for the C# project.


**Java**

Being that java does not have native libraries for Rijndael 256 bit block size, Bouncy Castle cryptography library was used. You will have to download this library and include it in the project.

To encrypt a file simply call the method "Encrypt"; supply it with a passphrase(at least 10 characters long), path to the file you wish to encrypt and the path to where you would like to have that then encrypted file saved.
To decrypt do the same, this time calling the "Decrypt" method.


#### File Structure 

 - 4 Octets __EN prefix used to check if a file is encrypted 
 - 1 Octet BitShuffle encryption version number 
 - 32 Octets iv used to encrypt the message iv and key
 - 32 Octets salt used to encrypt the message iv and key
 - 96 Octets encrypted iv and key 
 - 32 octets passphrase hmac used to authenticate the user passphrase
 - 10 Octets date created (purely optional)
 - 33 Octets unused
 - Encrypted message 
 - 32 Octets message hmac used to verify the message

My Android client is available at the [Google Play Store](https://play.google.com/store/apps/details?id=digitaltakesroot.com.BitShuffle)


