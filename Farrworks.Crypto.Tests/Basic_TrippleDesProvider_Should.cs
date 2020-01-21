using System;
using NUnit.Framework;
using Farrworks.Crypto.Basic;
using System.Security.Cryptography;
using System.Text;

namespace Farrworks.Crypto.Tests
{
   
    public class Basic_TrippleDesProvider_Should
    {
        [Test]
        public void EncryptAndDecrypt()
        {
            System.Diagnostics.Debugger.Launch();

            // generate a new random 192bit symetric key
            TripleDESCryptoServiceProvider csp = new TripleDESCryptoServiceProvider();
            csp.GenerateKey();
            string key = Convert.ToBase64String(csp.Key);
            
            // create our TripleDesProvider objects with our new key
            TripleDesProvider tdes1 = new TripleDesProvider(key);
            TripleDesProvider tdes2 = new TripleDesProvider(key);

            // test encryption and decription across tdes objects
            string toEncrypt = "this is a test";
            string cipherText = tdes1.BasicEncrypt(toEncrypt);
            string decryptedText = tdes2.BasicDecrypt(cipherText);

            Assert.That(decryptedText, Is.EqualTo(toEncrypt));
        }

        [Test]
        public void NotFailOnLargeKey()
        {
            System.Diagnostics.Debugger.Launch();
            Assert.DoesNotThrow(() =>
            {
                TripleDesProvider tdes1 = new TripleDesProvider("1q2w3e4r5t6y7u8i9o0p1q2w3e4r5t6y7u8i9o0pqawsedrftgyhujikolp");
            });
        }

        [Test]
        public void NotFailOnSmallKey()
        {
            System.Diagnostics.Debugger.Launch();
            Assert.DoesNotThrow(() =>
            {
                TripleDesProvider tdes1 = new TripleDesProvider("a");
            });
        }
    }
}
