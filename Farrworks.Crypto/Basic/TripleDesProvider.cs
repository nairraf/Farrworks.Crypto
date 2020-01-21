using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Farrworks.Crypto.Basic
{
    public class TripleDesProvider : IDisposable
    {
        private readonly byte[] _keyBytes;
        private TripleDESCryptoServiceProvider _tdesCrypto;
        private readonly string _salt;
        private readonly byte[] _saltBytes;

        public TripleDesProvider(string key)
        {
            // build a unique yet reproducable set of characters taken from our key to use as a salt
            for (int i=0; i<key.Length; i++)
            {
                if (i%3==0)
                {
                    _salt += key[i].ToString();
                }
            }

            // get a 64byte hash of our salt, we will use this as the salt byte array to generate the 24byte hash from our key
            SHA512CryptoServiceProvider sha = new SHA512CryptoServiceProvider();
            _saltBytes = sha.ComputeHash(Encoding.UTF8.GetBytes(_salt));
            sha.Dispose();

            // generate our final key, and assign to our 3DES object.
            _keyBytes = new Rfc2898DeriveBytes(key, _saltBytes, 1000).GetBytes(24);
            _tdesCrypto = new TripleDESCryptoServiceProvider();
            _tdesCrypto.Key = _keyBytes;
            _tdesCrypto.Mode = CipherMode.CBC;
        }

        public string Encrypt(string data)
        {
            byte[] buffer = Encoding.ASCII.GetBytes(data);
            string ret = "";
            try
            {
                string cipherText = Convert.ToBase64String(_tdesCrypto.CreateEncryptor().TransformFinalBlock(buffer, 0, buffer.Length));
                string iv = Convert.ToBase64String(_tdesCrypto.IV);
                // remove the = in the iv string, which is the last character
                iv = iv.Substring(0, iv.Length - 1);
                // bury the IV within the cipherText
                char[] combinedCipher = new char[iv.Length + cipherText.Length];
                int pointerIV = 0;
                int pointerCT = 0;
                for (int i=0; i<combinedCipher.Length; i++)
                {
                    if (i % 2 == 0 && pointerIV < iv.Length)
                    {
                        combinedCipher[i] = iv[pointerIV];
                        pointerIV++;
                    } 
                    else
                    {
                        combinedCipher[i] = cipherText[pointerCT];
                        pointerCT++;
                    }
                }
                ret = new string(combinedCipher);
            }
            catch
            {
                // do nothing for now
            }

            return ret;
        }

        public string Decrypt(string encryptedData)
        {
            //retrieve the IV that is burried within the cipherText
            char[] arrIV = new char[11];
            char[] arrCT = new char[24];
            int pointerIV = 0;
            int pointerCT = 0;

            // we have 11 characters of IV burried within the even indexes. extract them and assign them to arrIV. 
            // the rest is assigned to arrCT.
            for (int i=0; i<encryptedData.Length; i++)
            {
                if (i % 2 == 0 && pointerIV < arrIV.Length)
                {
                    arrIV[pointerIV] = encryptedData[i];
                    pointerIV++;
                }
                else
                {
                   arrCT[pointerCT] = encryptedData[i];
                   pointerCT++;
                }
            }

            string cipherText = new string(arrCT);
            string iv = new string(arrIV);
            // add back the trailing '=' sign for our IV
            iv = iv + "=";
            
            // assign our IV
            _tdesCrypto.IV = Convert.FromBase64String(iv);
          
            // get our buffer and decrypt.
            byte[] buffer = Convert.FromBase64String(cipherText);
            string ret = "";
            try
            {
                ret = Encoding.UTF8.GetString(_tdesCrypto.CreateDecryptor().TransformFinalBlock(buffer, 0, buffer.Length));
            }
            catch
            {
                // do nothing for now
            }
            return ret;
        }

        public void Dispose()
        {
            _tdesCrypto.Dispose();
        }
    }
}
