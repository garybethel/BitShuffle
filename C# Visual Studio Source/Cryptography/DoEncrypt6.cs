using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Linq;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;


namespace Cryptography
{
       
    public class DoEncry6
    {
        private Validate validator = new Validate();
        private byte[] passAuthenKeyEnc = new byte[32];
        private byte[] embeddedAuthenHmac = new byte[32];

        public bool Encrypt(string _userPassphrase, string filepath, string directoryPath, string fileName,
                            string fileExtension)
        {
            byte[] key = new byte[32];
            byte[] ben = Encoding.ASCII.GetBytes("__EN");
            const int bufferSize = 3200;
            byte[] enc = new byte[bufferSize];
            var header = new byte[4 + 1 + 64 + 96 + 10 + 65];
            const byte versionNumber = 0x06;
            byte[] dateCreated = Encoding.ASCII.GetBytes(DateTime.Now.ToString("dd/mm/yyyy"));
            byte[] messageRandomkeyPhrase = CreateRandonKeyPhrase();
            byte[] messageIV = GetIv();
            byte[] salt = GetSalt();
            byte[] firstIV = GetIv();
            bool result = true;
            FileStream fileStream = null;
            FileStream fr = null;
            try
            {
                Rfc2898DeriveBytes k1 = new Rfc2898DeriveBytes(messageRandomkeyPhrase, GetSalt(), 10000);
                key = k1.GetBytes(32);
                //We pass a randomly genereated iv and passphrase that are used to encrypt the iv and key for the message
                byte[] encryptedIVKeyPrefex = this.EncryptIVandKey(firstIV, _userPassphrase, salt, messageIV, key);

                using (Rijndael myRijndael = Rijndael.Create())
                {
                    myRijndael.BlockSize = 256;
                    myRijndael.IV = messageIV;
                    myRijndael.Key = key;
                    myRijndael.Mode = CipherMode.CBC;
                    myRijndael.Padding = PaddingMode.PKCS7;

                    bool prefixHeaderWritten = false;

                    using (ICryptoTransform cipher = myRijndael.CreateEncryptor())
                    {
                        FileInfo ff = new FileInfo(filepath);
                        byte[] buffer = new byte[bufferSize];
                        string savePath = this.GenerateFileName(filepath, directoryPath, fileName, fileExtension);
                        fileStream = new FileStream(savePath, FileMode.Create, FileAccess.Write);
                        
                        //We generate the hmac used for the userpassphrase 
                        byte[] passBuff = GeneratePassphaseHmac(firstIV, salt, passAuthenKeyEnc);

                        HMac hmac = new HMac(new Sha256Digest());
                        hmac.Init(new KeyParameter(key));
                        byte[] resBuf = new byte[hmac.GetMacSize()];
                        byte[] newmac = new byte[32];
                        // C# native Hmac
                        //HMACSHA256 hmac2 = new HMACSHA256(key);

                        int read = 0;
                        long aggregator = 0;               
                        using (fr = ff.OpenRead())
                        {
                            while ((read = fr.Read(buffer, 0, buffer.Length)) != 0)
                            {
                                if (prefixHeaderWritten == false)
                                {
                                    ////put the prefix __EN into the byte array called header
                                    Array.Copy(ben, 0, header, 0, ben.Length);
                                    //puts the file version byte into the header
                                    header[ben.Length] = versionNumber;
                                    //puts the iv into the header byte array
                                    Array.Copy(firstIV, 0, header, ben.Length + 1, firstIV.Length);
                                    //puts the salt into the header array
                                    Array.Copy(salt, 0, header, ben.Length + 1 + firstIV.Length,
                                               salt.Length);
                                    //puts the encrypted iv and key into the header array
                                    Array.Copy(encryptedIVKeyPrefex, 0, header, ben.Length + 1 + firstIV.Length + salt.Length
                                         , encryptedIVKeyPrefex.Length);
                                    //puts the hmac used to authenticate the user passphrase into the header)
                                    Array.Copy(passBuff, 0, header, ben.Length + 1 + firstIV.Length + salt.Length + encryptedIVKeyPrefex.Length, passBuff.Length);
                                    //puts the date created into the header
                                    Array.Copy(dateCreated, 0, header, ben.Length + 1 + firstIV.Length + salt.Length + encryptedIVKeyPrefex.Length +passBuff.Length
                                         , dateCreated.Length);

                                    fileStream.Write(header, 0, header.Length);
                                    prefixHeaderWritten = true;
                                }

                                if (aggregator + read != ff.Length)
                                {
                                    cipher.TransformBlock(buffer, 0, buffer.Length, enc, 0);
                                    hmac.BlockUpdate(enc, 0, enc.Length);
                                    fileStream.Write(enc, 0, enc.Length);
                                    aggregator += read;
                                }

                                else
                                {
                                    byte[] enc1 = cipher.TransformFinalBlock(buffer, 0, read);
                                    hmac.BlockUpdate(enc1, 0, enc1.Length);
                                    hmac.DoFinal(resBuf, 0);

                                    int enc1size = enc1.Length;
                                    Array.Resize(ref enc1, enc1.Length + resBuf.Length);
                                    Array.Copy(resBuf, 0, enc1, enc1size, resBuf.Length);

                                    fileStream.Write(enc1, 0, enc1.Length);
                                }

                            }
                        }
                      }         
                  }
            }          
            catch (Exception ex)
            {
                result = false;
            }
            finally
            {
                if (fileStream != null)
                {
                    fileStream.Flush();
                    fileStream.Close();
                }
                if (fr != null)
                {
                    fr.Close();
                }
            }
            if (!result)
            {
                return false;
            }
            return true;
        }

        public bool Decrypt(string _userPassphrase, string filepath, string directoryPath, string fileName, string fileExtension)
        {
            byte[] iv = new byte[32];
            const int bufferSize = 3200;
            byte[] enc = new byte[bufferSize];
            byte[] buffer = new byte[bufferSize];
            int read;
            byte[] header = new byte[240];
            byte[] encryptedCompositeIVKey = new byte[96];
            byte[] salt = new byte[32];
            byte[] messageEncryptionIV = new byte[32];
            byte[] messageEncryptionKey = new byte[32];
            FileStream fileStream = null;
            FileStream fr = null;
            CryptoStream cs = null;

            FileInfo ff = new FileInfo(filepath);
            try
            {
                using ( fr = ff.OpenRead())
                {
                    read = fr.Read(header, 0, header.Length);
           
                    //we extract the file version number
                    byte versionNumber = header[4];
                    if (versionNumber != 6)
                    {
                        throw new Exception("File version incompatible");
                    }
                    //extracts the iv from the header 
                    for (int i = 0; i < 32; i++)
                    {
                        iv[i] = header[i + 4 + 1];
                    }

                    //we extract the salt arrray
                    Array.Copy(header, 4 + 1 + iv.Length, salt, 0, salt.Length);
                    //we extract the bytes that represent the encrypted iv and key
                    Array.Copy(header, 4 + 1 + iv.Length + salt.Length, encryptedCompositeIVKey, 0, encryptedCompositeIVKey.Length);
                    //we extract the hmac used to authenticate the user's password
                    Array.Copy(header, 4 + 1 + iv.Length + salt.Length + encryptedCompositeIVKey.Length, embeddedAuthenHmac, 0, embeddedAuthenHmac.Length);
                    //decrypyt the composite iv and key
                    byte[] decryptedCompositeIVKey = DecryptIVandKey(iv, _userPassphrase, salt, encryptedCompositeIVKey);
                    //we extract the main message encryption iv and key after being decrypted above
                    Array.Copy(decryptedCompositeIVKey, 0, messageEncryptionIV, 0, messageEncryptionIV.Length);
                    Array.Copy(decryptedCompositeIVKey, 32, messageEncryptionKey, 0, messageEncryptionKey.Length);
                    //we extract the date here
                    byte[] dateCreated = new byte[10];
                    Array.Copy(header, 4 + 1 + iv.Length + salt.Length + encryptedCompositeIVKey.Length + embeddedAuthenHmac.Length, dateCreated, 0,
                               dateCreated.Length);
                    
                }

                HMac hmac = new HMac(new Sha256Digest());
                hmac.Init(new KeyParameter(messageEncryptionKey));
                byte[] resBuf = new byte[hmac.GetMacSize()];

                string savePath = this.GenerateFileName(filepath, directoryPath, fileName, fileExtension);
                fileStream = new FileStream(savePath, FileMode.Create, FileAccess.Write);

                using (Rijndael myRijndael = Rijndael.Create())
                {
                    myRijndael.BlockSize = 256;
                    myRijndael.IV = messageEncryptionIV;
                    myRijndael.Key = messageEncryptionKey;
                    myRijndael.Mode = CipherMode.CBC;
                    myRijndael.Padding = PaddingMode.PKCS7;
                    read = 0;

                    //var cipher = myRijndael.CreateDecryptor();
                    using (ICryptoTransform cipher = myRijndael.CreateDecryptor())
                    {                       
                        using (fr = ff.OpenRead())
                        {
                            cs = new CryptoStream(fileStream, cipher, CryptoStreamMode.Write);
                            //Set the stream to start after the header
                            fr.Seek(240, SeekOrigin.Begin);
                            long aggregator = 0;

                            while ((read = fr.Read(buffer, 0, buffer.Length)) != 0)
                            {
                                if (aggregator + read != ff.Length - 240)
                                {
                                    cs.Write(buffer, 0, read);
                                    hmac.BlockUpdate(buffer, 0, read);
                                    aggregator += read;
                                }
                                else
                                {
                                    //32 is subtracted from the read lenght so as to not include the Hmac at the end
                                    hmac.BlockUpdate(buffer, 0, read - 32);
                                    hmac.DoFinal(resBuf, 0);

                                    cs.Write(buffer, 0, read - 32);
                                    cs.FlushFinalBlock();

                                    byte[] embededHmac = new byte[32];
                                    //we extract the hmac from the file and place it into its own array
                                    Array.Copy(buffer, read - 32, embededHmac, 0, embededHmac.Length);
                                    if (this.CompareHmacs(embededHmac, resBuf) == false)
                                    {
                                        return false;
                                    }
                                }
                            }
                        }                
                    }
                }            
            }
            catch (Exception ex)
            {
                return false;
            }
            finally
            {
                if (fr != null) {
                    fr.Close();
                }
                if (cs != null)
                {
                    cs.Close();
                }
                //fileStream.Flush();
                if (fileStream != null)
                {
                    fileStream.Close();
                }               
            }
            return true;
        }


        public Boolean ChangePassphrase (string _userPassphrase,String newUserPassphrase, string filepath, string directoryPath, string fileName, string fileExtension)
        {
            byte[] iv = new byte[32];
            //buffer cannot be less than 40 due it having to read the file prefix and IV
            byte[]  ben = Encoding.ASCII.GetBytes("__EN");
            const int bufferSize = 3200;
            byte[] enc = new byte[bufferSize];
            byte[] buffer = new byte[bufferSize];
            byte[] header = new byte[240];
            int read;
            byte[] encryptedCompositeIVKey = new byte[96];
            byte[] salt = new byte[32];
            byte[] messageEncryptionIV = new byte[32];
            byte[] messageEncryptionKey = new byte[32];
            string savePath;

            FileInfo ff = new FileInfo(filepath);
            FileStream outStream = null;
            try
            {
                using (FileStream fr = ff.OpenRead())
                {
                    read = fr.Read(header, 0, header.Length);

                    //we extract the file version number
                    byte versionNumber = header[4];
                    if (versionNumber != 6)
                    {
                        throw new System.ArgumentException("File version incompatible");
                    }
                    //extracts the iv from the buffer 
                    for (int i = 0; i < 32; i++)
                    {
                        iv[i] = header[i + 4 + 1];
                    }

                    //we extract the salt arrray
                    Array.Copy(header, 4 + 1 + iv.Length, salt, 0, salt.Length);
                    //we extract the bytes that represent the encrypted iv and key
                    Array.Copy(header, 4 + 1 + iv.Length + salt.Length, encryptedCompositeIVKey, 0, encryptedCompositeIVKey.Length);
                    //we extract the hmac used to authenticate the user's password
                    Array.Copy(header, 4 + 1 + iv.Length + salt.Length + encryptedCompositeIVKey.Length, embeddedAuthenHmac, 0, embeddedAuthenHmac.Length);
                    //decrypyt the composite iv and key
                    byte[] decryptedCompositeIVKey = DecryptIVandKey(iv, _userPassphrase, salt, encryptedCompositeIVKey);
                   
                    ///////////////////////////////////////

                    //we extract the main message encryption iv and key after being decrypted above
                    Array.Copy(decryptedCompositeIVKey, 0, messageEncryptionIV, 0, messageEncryptionIV.Length);
                    Array.Copy(decryptedCompositeIVKey, 32, messageEncryptionKey, 0, messageEncryptionKey.Length);
                    //we extract the date here
                    byte[] dateCreated = new byte[10];
                    Array.Copy(header, 4 + 1 + iv.Length + salt.Length + encryptedCompositeIVKey.Length + embeddedAuthenHmac.Length, dateCreated, 0,
                               dateCreated.Length);

                    salt = GetSalt();
                    byte[] firstIV = GetIv();
                    byte[] encryptedIVKeyPrefex = this.EncryptIVandKey(firstIV, newUserPassphrase, salt, messageEncryptionIV, messageEncryptionKey);
                    //we now need to create a new passphrase hmac using the new passphrase
                    byte[] passBuff = GeneratePassphaseHmac(firstIV, salt, passAuthenKeyEnc);

                    savePath = this.GenerateFileNewName(filepath, directoryPath, fileName, fileExtension);
                    outStream = new FileStream(savePath, FileMode.Create, FileAccess.Write);
                    
                    read = 0;
                    bool prefixHeaderWritten = false;
                    while ((read = fr.Read(buffer, 0, buffer.Length)) != 0)
                    {
                        if (prefixHeaderWritten == false)
                        {
                            ////put the prefix __EN into the byte array called header
                            Array.Copy(ben, 0, header, 0, ben.Length);
                            //puts the file version byte into the header
                            header[ben.Length] = versionNumber;
                            //puts the iv into the header byte array
                            Array.Copy(firstIV, 0, header, ben.Length + 1, firstIV.Length);
                            //puts the salt into the header array
                            Array.Copy(salt, 0, header, ben.Length + 1 + firstIV.Length,
                                       salt.Length);
                            //puts the encrypted iv and key into the header array
                            Array.Copy(encryptedIVKeyPrefex, 0, header, ben.Length + 1 + firstIV.Length + salt.Length
                                 , encryptedIVKeyPrefex.Length);
                            //puts the hmac used to authenticate the user passphrase into the header)
                            Array.Copy(passBuff, 0, header, ben.Length + 1 + firstIV.Length + salt.Length + encryptedIVKeyPrefex.Length, passBuff.Length);
                            //puts the date created into the header
                            Array.Copy(dateCreated, 0, header, ben.Length + 1 + firstIV.Length + salt.Length + encryptedIVKeyPrefex.Length + passBuff.Length
                                 , dateCreated.Length);

                            outStream.Write(header, 0, header.Length);
                            prefixHeaderWritten = true;
                        }   
                        outStream.Write(buffer, 0, read);
                    }
                    fr.Close();
                }               
            }
            catch (Exception ex)
            {
                return false;
            }
            finally
            {
                outStream.Close();
            }
            //we delete the existing esf file and rename the newly created .new file to the standard .esf
            if (DeleteFile(filepath))
            {
                RenameFile(savePath, filepath);
            }
        return true;
        }

        private Boolean DeleteFile(String filepath) {
            try
            {
                File.Delete(filepath); 
                return true;
            }
            catch (IOException)
            {
                return false;
            }     
        }

        private Boolean RenameFile(String filePath, String newFilePath)
        {
            try
            {
                File.Move(filePath, newFilePath);
                return true;
            }
            catch (IOException ex)
            {
                return false;
            }
        }

        private byte[] GeneratePassphaseHmac(byte[] iv, byte[] salt, byte[] key)
        {
            HMac userPhraseHmac = new HMac(new Sha256Digest() );
            byte[] passBuff = new byte[userPhraseHmac.GetMacSize()];
            userPhraseHmac.Init(new KeyParameter(key));
            userPhraseHmac.BlockUpdate(iv, 0, iv.Length);
            userPhraseHmac.BlockUpdate(salt, 0, salt.Length);
            userPhraseHmac.DoFinal(passBuff, 0);
            return passBuff;
        }

        private byte[] GetIv()
        {
            //Generate a cryptographic random number.
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] buff = new byte[32];
            rng.GetBytes(buff);
            return buff;
        }


        private byte[] CreateRandonKeyPhrase()
        {
            //Generate a cryptographic random number.
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] buff = new byte[40];
            rng.GetBytes(buff);
            return buff;
        }


        private byte[] GetSalt()
        {
            //Generate a cryptographic random number.
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] buff = new byte[32];
            rng.GetBytes(buff);
            return buff;
        }


        private string GenerateFileNewName(string filepath, string directoryPath, string fileName, string fileExtension)
        {
                //if the filename extension is .esf
                int lastIndexOfDot = fileName.LastIndexOf(".", System.StringComparison.Ordinal);
                fileExtension = fileName.Substring(lastIndexOfDot, fileName.Length - lastIndexOfDot);
                fileName = fileName.Substring(0, fileName.Length - (fileName.Length - lastIndexOfDot));
                String tempExtension = ".new";

                if (File.Exists(directoryPath + "\\" + fileName + fileExtension + tempExtension) == true)
                {
                    Match match = Regex.Match(fileName, "\\([0-99]+\\)");
                    if (match.Success)
                    {     
                        int startingIndex = match.Index;
                        int endingIndex = match.Index + match.Length;
                        //we then find the string digit that is enclosed by that bracket
                        string stringDigit = fileName.Substring(startingIndex + 1,
                                                                (endingIndex - 1) - (startingIndex + 1));
                        int digit = Convert.ToInt32(stringDigit);
                        //we then get the file name without the bracket inclosed integer
                        string newFileName = fileName.Substring(0, fileName.Length - 3);
                        //find if the file with the incremented bracketed integer exits if so we increment the integer
                        while (File.Exists(directoryPath + "\\" + newFileName + "(" + digit + ")" + fileExtension + tempExtension))
                        {
                            digit++;
                        }
                        return directoryPath + "\\" + newFileName + "(" + digit + ")" + fileExtension + tempExtension;
                    }
                    else
                    {
                        int iterator = 2;
                        while (File.Exists(directoryPath + "\\" + fileName + "(" + iterator + ")" + fileExtension + tempExtension))
                        {
                            iterator++;
                        }
                        return directoryPath + "\\" + fileName + "(" + iterator + ")" + fileExtension + tempExtension;
                    }
                }
                return directoryPath + "\\" + fileName + fileExtension + tempExtension;
        }

        private string GenerateFileName(string filepath, string directoryPath, string fileName, string fileExtension)
        {
            if (!fileExtension.ToLower().Equals(".esf"))
            {
                const string newFileExtension = ".esf";

                if (File.Exists(directoryPath + "\\" + fileName + fileExtension + newFileExtension) == true)
                {
                    Match match = Regex.Match(fileName, "\\([0-99]+\\)");
                    if (match.Success)
                    {
                        int startingIndex = match.Index;
                        int endingIndex = match.Index + match.Length;
                        //we then find the string digit that is enclosed by that bracket
                        string stringDigit = fileName.Substring(startingIndex + 1, (endingIndex - 1) - (startingIndex + 1));
                        //we convert that string into an integer so we could increment it
                        int digit = Convert.ToInt32(stringDigit);
                        //we then get the file name without the bracket inclosed integer
                        string newFileName = fileName.Substring(0, fileName.Length - 3);
                        //find if the file with the incremented bracketed integer exits if so we increment the integer
                        while (File.Exists(directoryPath + "\\" + newFileName + "(" + digit + ")" + fileExtension + newFileExtension))
                        {
                            digit++;
                        }
                        return directoryPath + "\\" + newFileName + "(" + digit + ")" + fileExtension + newFileExtension;
                    }

                    else
                    {
                        int iterator = 2;
                        while (File.Exists(directoryPath + "\\" + fileName + "(" + iterator + ")" + fileExtension + newFileExtension))
                        {
                            iterator++;
                        }
                        return directoryPath + "\\" + fileName + "(" + iterator + ")" + fileExtension + newFileExtension;
                    }
                }
                return directoryPath + "\\" + fileName + fileExtension + newFileExtension;
            }
            else
            {           
                //if the filename extension is .esf
                int lastIndexOfDot = fileName.LastIndexOf(".", System.StringComparison.Ordinal);
                fileExtension = fileName.Substring(lastIndexOfDot, fileName.Length - lastIndexOfDot);
                fileName = fileName.Substring(0, fileName.Length - (fileName.Length - lastIndexOfDot));

                if (File.Exists(directoryPath + "\\" + fileName + fileExtension) == true)
                {
                    Match match = Regex.Match(fileName, "\\([0-99]+\\)");
                    if (match.Success)
                    {
                        int startingIndex = match.Index;
                        int endingIndex = match.Index + match.Length;
                        //we then find the string digit that is enclosed by that bracket
                        string stringDigit = fileName.Substring(startingIndex + 1,
                                                                (endingIndex - 1) - (startingIndex + 1));
                        int digit = Convert.ToInt32(stringDigit);
                        //we then get the file name without the bracket inclosed integer
                        string newFileName = fileName.Substring(0, fileName.Length - 3);
                        //find if the file with the incremented bracketed integer exits if so we increment the integer
                        while (File.Exists(directoryPath + "\\" + newFileName + "(" + digit + ")" + fileExtension))
                        {
                            digit++;
                        }
                        return directoryPath + "\\" + newFileName + "(" + digit + ")" + fileExtension;
                    }
                    else
                    {
                        int iterator = 2;
                        while (File.Exists(directoryPath + "\\" + fileName + "(" + iterator + ")" + fileExtension))
                        {
                            iterator++;
                        }
                        return directoryPath + "\\" + fileName + "(" + iterator + ")" + fileExtension;
                    }
                }
                return directoryPath + "\\" + fileName + fileExtension;
            }
        }


        private bool CompareHmacs(byte[] hMac1, byte[] hMac2)
        {
            return !hMac1.Where((t, j) => t != hMac2[j]).Any();
        }

        private byte[] EncryptIVandKey(byte[] _userIv, String _userPassphrase, byte[] _salt, byte[] _messageIV, byte[] _messageKey)
        {
            int blockSize = 256;
            int keySize = 32;
            byte[] compositeIVKey = new byte[_messageKey.Length + _messageIV.Length];
            Array.Copy(_messageIV, 0, compositeIVKey, 0, _messageIV.Length);
            Array.Copy(_messageKey, 0, compositeIVKey, _messageIV.Length, _messageKey.Length);
            Rfc2898DeriveBytes k1 = new Rfc2898DeriveBytes(_userPassphrase, _salt, 10000);
            byte[] key = k1.GetBytes(keySize);
            passAuthenKeyEnc = key;
            try
            {
                using (Rijndael myRijndael = Rijndael.Create())
                {
                    myRijndael.BlockSize = blockSize;
                    myRijndael.IV = _userIv;
                    myRijndael.Key = key;
                    myRijndael.Mode = CipherMode.CBC;
                    myRijndael.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform ict = myRijndael.CreateEncryptor())
                    {
                        byte[] encryptedMessage = ict.TransformFinalBlock(compositeIVKey, 0, compositeIVKey.Length);
                        return encryptedMessage;
                    }
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }         
        }

        private byte[] DecryptIVandKey(byte[] _userIv, String _userPassphrase, byte[] _salt, byte[] _compositeIVKey)
        {
            int blockSize = 256;
            int keySize = 32;
            byte[] decryptedMessage = new byte[64];
            Rfc2898DeriveBytes k1 = new Rfc2898DeriveBytes(_userPassphrase, _salt, 10000);
            byte[] key = k1.GetBytes(keySize);
            byte[] passAuthenKeyDec = key;

            try
            {
                using (Rijndael myRijndael = Rijndael.Create())
                {
                    myRijndael.BlockSize = blockSize;
                    myRijndael.IV = _userIv;
                    myRijndael.Key = key;
                    myRijndael.Mode = CipherMode.CBC;
                    myRijndael.Padding = PaddingMode.PKCS7;
                    byte[] passBuff = GeneratePassphaseHmac(_userIv, _salt, passAuthenKeyDec);
                    //compute the hmac of the users passphrase using the embedded iv and salt 
                    if (!passBuff.SequenceEqual(embeddedAuthenHmac))
                    {         
                        throw new Exception("Incorrect password");
                    }
                    using (ICryptoTransform ict = myRijndael.CreateDecryptor())
                    {
                        decryptedMessage = ict.TransformFinalBlock(_compositeIVKey, 0, _compositeIVKey.Length);
                    }
                    return decryptedMessage;
                }
            }
            catch (Exception ex) 
            {
                throw ex;        
            }
        }

    }
}


