using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace Cryptography
{
    public class Validate
    {
        public bool IsFileEncrypted(string filepath)
        {
            FileInfo ff = new FileInfo(filepath);
            byte[] buffer = new byte[4];
            byte[] iv = new byte[4];
            FileStream fr= null;
            try
            {
                using (fr = ff.OpenRead())
                {
                    var read = fr.Read(buffer, 0, buffer.Length);   
                }
           
                //puts the iv from data into the iv string 
                for (int i = 0; i < 4; i++)
                {
                    iv[i] = buffer[i];
                }

                if (Encoding.Default.GetString(iv) == "__EN")
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception e)
            {
                return false;
            }
            finally
            {
                if (fr != null)
                {
                    fr.Close();
                }
            }
        }
     
        public int ChkFileVersion(string filepath)
        {
            FileInfo ff = new FileInfo(filepath);
            byte[] buffer = new byte[8];
            byte versionNum;
            FileStream fr = null;
            try
            {
                using (fr = ff.OpenRead())
                {
                    var read = fr.Read(buffer, 0, buffer.Length);
                }
            }

            catch (Exception e)
            {
                return 0;
            }
            finally
            {
                if (fr != null) 
                {
                    fr.Close();
                } 
            }
            //puts the iv from data into the iv string 
            versionNum = buffer[4];
            return versionNum;
        }
    }
}
