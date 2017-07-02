using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace Cryptography
{
    class Program
    {
        static void Main(string[] args)
        {
            Program program = new Program();

            string rootPath = AppDomain.CurrentDomain.BaseDirectory;
            byte[] sourceData = program.ReadFile(rootPath + "\\test.docx");
            byte[] encryptedData= program.Encrypt(sourceData);
            program.WriteFile(rootPath + "\\encryption\\test.docx", encryptedData);

            byte[] destinationData = program.ReadFile(rootPath + "\\encryption\\test.docx");
            byte[] decryptedData = program.Decrypt(destinationData);
            program.WriteFile(rootPath + "\\decryption\\test.docx", decryptedData);

        }

        private byte[] Encrypt(byte[] data)
        {
            string Key = "passwordDR0wSS@P6660juht";
            string IV = "password";
            string enc1 = Encoding.Default.GetString(data);
            enc1 += "___EOT";
            data = Encoding.Default.GetBytes(enc1);
            byte[] key = Encoding.ASCII.GetBytes(Key);
            byte[] iv = Encoding.ASCII.GetBytes(IV);

            byte[] enc = new byte[0];
            TripleDES tdes = TripleDES.Create();
            tdes.IV = iv;
            tdes.Key = key;
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.Zeros;
            ICryptoTransform ict = tdes.CreateEncryptor();
            enc = ict.TransformFinalBlock(data, 0, data.Length);

            data = Encoding.UTF8.GetBytes(Convert.ToBase64String(enc));

            return data;
        }

        private byte[] Decrypt(byte[] data)
        {
            string Key = "passwordDR0wSS@P6660juht";
            string IV = "password";
            byte[] enc = new byte[0];
            byte[] key = Encoding.ASCII.GetBytes(Key);
            byte[] iv = Encoding.ASCII.GetBytes(IV);


            TripleDES tdes = TripleDES.Create();
            tdes.IV = iv;
            tdes.Key = key;
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.Zeros;
            ICryptoTransform ict = tdes.CreateDecryptor();

            data = Convert.FromBase64String(Encoding.UTF8.GetString(data));
            enc = ict.TransformFinalBlock(data, 0, data.Length);
            string enc1 = Encoding.Default.GetString(enc);
            enc1 = enc1.Substring(0, enc1.IndexOf("___EOT"));

            enc = Encoding.Default.GetBytes(enc1);

            return enc;
        }

        private byte[] ReadFile(string path)
        {
            byte[] fileContents = null;

            try
            {
                FileInfo ff = new FileInfo(path);
                fileContents = new byte[ff.Length];
                using (FileStream fr = ff.OpenRead())
                {
                    fr.Read(fileContents, 0, Convert.ToInt32(ff.Length));
                }

            }
            catch (Exception ex)
            {
                throw;
            }
            return fileContents;
        }


        private void WriteFile(string path, byte[] data)
        {
            FileStream fileStream = new FileStream(path, FileMode.Create, FileAccess.Write);
            fileStream.Write(data, 0, data.Length);
            fileStream.Close();
        }
    }
}
