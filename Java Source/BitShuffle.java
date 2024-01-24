package doencrypt;

import java.io.*;
import java.nio.channels.FileChannel;
import java.security.SecureRandom;
import java.util.*;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import java.util.Date;
import java.text.SimpleDateFormat;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.paddings.PKCS7Padding;


public class BitShuffle {

 private byte[] passAuthenEncKey = new byte [32];
 private byte[] embeddedAuthenHmac = new byte[32];

public boolean Encrypt(String userPassphrase, String filePath, String savePath)
{
    final byte[] ben = "__EN".getBytes();
    //stream reader readBuffer size
    int bufferSize = 3200;
    byte[] readBuffer = new byte[bufferSize];
    int blockSize = 256;
    int keySize = 32;
    byte[] header = new byte[4 + 1 + 32 + 32 + 96 + 10 + 65];
    byte versionNumber = (byte)0x06;
    
    byte[] salt = RndNumGen(32);
    byte[] keyEncryptionIv = RndNumGen(32);
    FileOutputStream outStream = null;
    FileInputStream fr = null;

    SimpleDateFormat dateFormat = new SimpleDateFormat("dd/mm/yyyy");
    Date date = new Date();
    byte[] dateCreated = dateFormat.format(date).getBytes();
    boolean result = true;
    //Randomly generated the keyEncryptionIv and key that would be used for the message encryption
    byte[] messageRandomkeyPhrase = RndNumGen(40);
    byte[] messageIV= RndNumGen(32);

    try{
        PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
        generator.init(PBEParametersGenerator
                  .PKCS5PasswordToUTF8Bytes((new String(messageRandomkeyPhrase, "UTF-8"))
                  .toCharArray()), RndNumGen(32)/*used for salt*/, 10000);

        KeyParameter params = (KeyParameter)generator.generateDerivedParameters(256);
        //256 bit key
        byte[]key = params.getKey();

        //We pass a randomly genereated keyEncryptionIv and the Key used to encrypt the main message,
        //to be encrypted using the user's passphrase and random IV
        byte[] encryptedIVKeyPrefex = EncryptIVandKey(keyEncryptionIv, userPassphrase,salt, messageIV,key );

        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
        new CBCBlockCipher(new RijndaelEngine(blockSize)), new PKCS7Padding());

        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key, 0, keySize), messageIV, 0, keySize);
        cipher.init(true, ivAndKey);
        //generate the hmac of the users passphrase using the embedded keyEncryptionIv and salt
        byte[] passBuff = GeneratePassphaseHmac(keyEncryptionIv, salt, passAuthenEncKey);

        //Hmac used to authenticate the validity of the message
        HMac messageHmac = new HMac(new SHA256Digest());
        byte[] messageHmacBuf = new byte[messageHmac.getMacSize()];
        messageHmac.init(new KeyParameter(key));

         fr = new FileInputStream(filePath);
         outStream = new FileOutputStream (savePath);

         long fileLength = fr.available();
         if(fileLength == 0)
         {
             throw new IllegalArgumentException("File size error");
         }
         long aggregator = 0;
         int read = 0;
         int readLength = 0;

         boolean headerWritten = false;
         while ((read = fr.read(readBuffer)) != -1)
         {
          if (headerWritten == false)
          {
              System.arraycopy(ben, 0,header , 0, ben.length);
              //puts the readLength version byte into the header
              header[ben.length] = versionNumber;
              //puts the encrypted keyEncryptionIv used to encrypt the key into the header
              System.arraycopy(keyEncryptionIv,0, header, ben.length + 1, keyEncryptionIv.length);
              //salt used to encrypt the messsage keyEncryptionIv and key
              System.arraycopy(salt,0, header, ben.length + 1 + keyEncryptionIv.length, salt.length);
              //puts the encrypted Iv and key into the header array
              System.arraycopy(encryptedIVKeyPrefex,0, header, ben.length + 1 + keyEncryptionIv.length+salt.length
                      , encryptedIVKeyPrefex.length);
              //puts the hmac used to authenticate the user passphrase into the header)
              System.arraycopy(passBuff,0,header , ben.length +1+ keyEncryptionIv.length+salt.length + encryptedIVKeyPrefex.length, passBuff.length);
              //puts the date created into the header
              System.arraycopy(dateCreated, 0,header , ben.length + 1 + keyEncryptionIv.length+salt.length + encryptedIVKeyPrefex.length + passBuff.length
                      , dateCreated.length);
              outStream.write(header,0,header.length);
              headerWritten = true;
          }

          if(aggregator+read!= fileLength)
          {
              byte[] cipherBuffer = new byte[cipher.getUpdateOutputSize(read)];
              readLength += cipher.processBytes(readBuffer, 0, read,  cipherBuffer, 0);
              outStream.write(cipherBuffer,0, cipherBuffer.length);
              messageHmac.update(cipherBuffer, 0,  cipherBuffer.length);
              aggregator += read;
          }
          else
          {
              byte[]cipherBuffer = new byte[cipher.getOutputSize(read)];
              readLength = cipher.processBytes(readBuffer, 0, read, cipherBuffer, 0);
              cipher.doFinal(cipherBuffer, readLength);
              messageHmac.update(cipherBuffer, 0, cipherBuffer.length);
              messageHmac.doFinal(messageHmacBuf, 0);

              byte[] bufferPlusHmac = new byte[cipherBuffer.length + messageHmacBuf.length];
              //copies last encrypted cipherBuffer data into the bufferPlusHmac
              System.arraycopy(cipherBuffer, 0,bufferPlusHmac , 0, cipherBuffer.length);
              System.arraycopy(messageHmacBuf, 0, bufferPlusHmac, cipherBuffer.length, messageHmacBuf.length);
              outStream.write(bufferPlusHmac,0,bufferPlusHmac.length);
          }
         }
         outStream.flush();
    }
    catch (IOException | IllegalArgumentException | IllegalStateException | DataLengthException | InvalidCipherTextException e)
    {
        System.out.println(e.toString());
        result = false;
    }
    finally
    {
        try
        {
            if(outStream != null)
            {
                outStream.close();
            }
            if(fr != null)
            {
                fr.close();
            }
        }
        catch (IOException e)
        {
            System.out.println(e.toString());
            result = false;
        }
    }
    if(!result)
    {
      return false;
    }
    return true; 
}

public boolean Decrypt(String userPassphrase, String filepath, String savePath)
{
    byte[] keyEncryptionIv = new byte[32];
    byte[] salt = new byte[32];
	//stream reader buffer size
    int bufferSize = 3200;
    byte[] readBuffer = new byte[bufferSize];
    int blockSize = 256;
    int keySize = 32;
    //header where the encrypted (Iv,Salt), (Iv,Key), date is stored
    byte[] header = new byte[240];
    byte[] messageEncryptionIV = new byte[32];
    byte[] messageEncryptionKey = new byte[32];

    FileOutputStream outStream = null;
    FileInputStream fr = null;
    boolean result = true;
    byte[] encryptedCompositeIVKey = new byte[96];

    try
    {
        fr = new FileInputStream(filepath);
        FileChannel fc = fr.getChannel();
        fr.read(header,0,header.length);
        byte versionNumber= header[4];

        if (versionNumber!= 0x06)
        {
            return false;
        }
        //we extract the keyEncryptionIv
        System.arraycopy(header, 4 + 1, keyEncryptionIv, 0, keyEncryptionIv.length);
        //we extract the salt arrray
        System.arraycopy(header, 4 + 1 +keyEncryptionIv.length, salt, 0, salt.length);
        //we extract the bytes that represent the encrypted keyEncryptionIv and key
        System.arraycopy(header, 4+1 +keyEncryptionIv.length + salt.length, encryptedCompositeIVKey, 0, encryptedCompositeIVKey.length);
        //we extract the hmac used to authenticate the user's password
        System.arraycopy(header,4 + 1 + keyEncryptionIv.length +salt.length+encryptedCompositeIVKey.length, embeddedAuthenHmac, 0, embeddedAuthenHmac.length);
        //decrypyt the composite Iv and key
        byte[] decryptedCompositeIVKey = DecryptIVandKey(keyEncryptionIv,userPassphrase, salt,encryptedCompositeIVKey);
        if(decryptedCompositeIVKey == null)
        {   
            //file most likely corrupt
            return false;    
        }
        
        ///////////////////////////////////////
        //we extract the main message encryption keyEncryptionIv and key after being decrypted above
        System.arraycopy(decryptedCompositeIVKey, 0, messageEncryptionIV, 0, messageEncryptionIV.length);
        System.arraycopy(decryptedCompositeIVKey, 32, messageEncryptionKey, 0, messageEncryptionKey.length);
        //we extract the date here
        byte[] dateCreated= new byte[10];
        System.arraycopy(header,4 + 1 + keyEncryptionIv.length + salt.length+encryptedCompositeIVKey.length+embeddedAuthenHmac.length, dateCreated,0,dateCreated.length);
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
        new CBCBlockCipher(new RijndaelEngine(blockSize)), new PKCS7Padding());

        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(messageEncryptionKey, 0, keySize), messageEncryptionIV, 0, keySize);
        cipher.init(false, ivAndKey);

        HMac hmac = new HMac(new SHA256Digest());
        byte[] hmacBuffer = new byte[hmac.getMacSize()];
        hmac.init(new KeyParameter(messageEncryptionKey));

        outStream = new FileOutputStream (savePath);
        CipherOutputStream cos = new CipherOutputStream(outStream, cipher);

        //sets the readLength channel position to read after the header
        fc.position(240);
        long fileLength = fr.available();
        int lastRead = 0;
        long aggregator = 0;
        int read = 0;

        while ((read = fr.read(readBuffer)) !=-1)
        {
            if(aggregator+read != fileLength)
            {
                cos.write(readBuffer,0,read);
                hmac.update(readBuffer, 0, readBuffer.length);
                aggregator +=read;
            }
            else
            {   //we minus 32 there since we dont want to include the message
                //hmac
                hmac.update(readBuffer, 0, read-32);
                hmac.doFinal(hmacBuffer, 0);
                cos.write(readBuffer,0,read-32);
                lastRead = read;
            }
        }
          cos.flush();
          cos.close();
		  
          byte[] embeddedHmac = new byte[32];
          System.arraycopy(readBuffer, lastRead-32, embeddedHmac, 0, embeddedHmac.length);
          if (!Arrays.equals(hmacBuffer, embeddedHmac))
          {
              result = false;
          }
    }

    catch (IOException | IllegalArgumentException |InvalidCipherTextException e)
    {
        System.out.println(e.toString());
        result = false;
    }
    finally
    {
        try
        {
            if(outStream != null)
            {
                outStream.close();
            }
            if(fr != null)
            {
                fr.close();
            }
        }
        catch (IOException e)
        {
            System.out.println(e.toString());
            result =false;
        }
    }
    if(!result)
    {
      return false;
    }
    return true;
}

private byte[] GeneratePassphaseHmac(byte[] iv, byte[] salt, byte [] key)
{
    //create hmac using the key from the previous and the messageIV
    HMac userPhraseHmac = new HMac(new SHA256Digest());
    byte[] passBuff = new byte[userPhraseHmac.getMacSize()];
    userPhraseHmac.init(new KeyParameter(key));
    userPhraseHmac.update(iv,0,iv.length);
    userPhraseHmac.update(salt,0,salt.length);
    userPhraseHmac.doFinal(passBuff,0);
    return passBuff;
}
 
private byte[] RndNumGen(int size)
{
    SecureRandom random = new SecureRandom();
    byte phrase[] = new byte[size];
    random.nextBytes(phrase);
    return phrase;
}

private byte[] EncryptIVandKey(byte[] userIv, String userPassphrase, byte[]salt ,byte[] messageIV, byte[] messageKey) throws IllegalArgumentException, DataLengthException, IllegalStateException, InvalidCipherTextException
{
    int blockSize = 256;
    int keySize = 32;
    byte [] compositeIVKey = new byte[messageKey.length+messageIV.length];

    System.arraycopy(messageIV, 0, compositeIVKey, 0, messageIV.length);
    System.arraycopy(messageKey, 0, compositeIVKey, messageIV.length, messageKey.length);
    try
    {
         PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
         generator.init(PBEParametersGenerator
                  .PKCS5PasswordToUTF8Bytes((userPassphrase)
                  .toCharArray()), salt, 10000);

        KeyParameter params = (KeyParameter)generator.generateDerivedParameters(256);
        byte[] key = params.getKey();
        passAuthenEncKey = key;

        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
        new CBCBlockCipher(new RijndaelEngine(blockSize)), new PKCS7Padding());

        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key, 0, keySize), userIv, 0, keySize);

        cipher.init(true, ivAndKey);

        cipher.getOutputSize(compositeIVKey.length);
        byte[] encryptedMessage = new byte[cipher.getOutputSize(compositeIVKey.length)];

        int lenght = cipher.processBytes(compositeIVKey, 0, compositeIVKey.length, encryptedMessage, 0);
        lenght+= cipher.doFinal(encryptedMessage, lenght);

        return encryptedMessage;
    }
    catch(IllegalArgumentException | IllegalStateException | DataLengthException | InvalidCipherTextException e)
    {
        throw e;
    }
}

private byte[] DecryptIVandKey(byte[] iv, String userPassphrase, byte[] salt ,byte[] compositeIVKey) throws InvalidCipherTextException
{
    int blockSize = 256;
    int keySize = 32;
    try
    {
         PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
         generator.init(PBEParametersGenerator
                  .PKCS5PasswordToUTF8Bytes((userPassphrase)
                  .toCharArray()), salt, 10000);

        KeyParameter params = (KeyParameter)generator.generateDerivedParameters(256);
        byte[] key = params.getKey();
        byte[] passAuthenDecKey = key;
        //generate the hmac of the users passphrase using the embedded keyEncryptionIv and salt
        byte[] passBuff = GeneratePassphaseHmac(iv, salt, passAuthenDecKey);
        if (!Arrays.equals(passBuff, embeddedAuthenHmac))
        {
             //incorrect password supplied
            throw new InvalidCipherTextException("Incorrect password");
        }
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
        new CBCBlockCipher(new RijndaelEngine(blockSize)), new PKCS7Padding());

        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key, 0, keySize), iv, 0, keySize);
        cipher.init(false, ivAndKey);

        byte[] decryptedMessage = new byte[64];

        int length = cipher.processBytes(compositeIVKey, 0, compositeIVKey.length, decryptedMessage, 0);
        length += cipher.doFinal(decryptedMessage, length);

        return decryptedMessage;
    }
    catch(IllegalArgumentException | IllegalStateException | DataLengthException | InvalidCipherTextException e)
    {      
        throw e;
    }
}


}
