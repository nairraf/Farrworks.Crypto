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
            // generate a new random 192bit symetric key
            TripleDESCryptoServiceProvider csp = new TripleDESCryptoServiceProvider();
            csp.GenerateKey();
            string key = Convert.ToBase64String(csp.Key);
            
            // create our TripleDesProvider objects with our new key
            TripleDesProvider tdes1 = new TripleDesProvider(key);
            TripleDesProvider tdes2 = new TripleDesProvider(key);

            // test encryption and decription across tdes objects
            string toEncrypt = "this is a test";
            string cipherText = tdes1.Encrypt(toEncrypt);
            string decryptedText = tdes2.Decrypt(cipherText);

            Assert.That(decryptedText, Is.EqualTo(toEncrypt));
        }

        [Test]
        public void EncryptAndDecryptWithLargeKey()
        {
            string key = @"1q2w3e4r5t6y7u8i9o0p1q2w3e4r5t6y7u8i9o0pqawsedrftgyhujikolp84hnfiusfd872349jsakmnbsdiIUBGFD*^jO)j2kjnDHKJFO9@1ml!\kj872jhbkmnsdg9835489ajikhakjdaf-+=lkjnasfkjb98jkkj2349809sifhd";
            // create our TripleDesProvider objects with our new key
            TripleDesProvider tdes1 = new TripleDesProvider(key);
            TripleDesProvider tdes2 = new TripleDesProvider(key);

            // test encryption and decription across tdes objects
            string toEncrypt = "this is a test";
            string cipherText = tdes1.Encrypt(toEncrypt);
            string decryptedText = tdes2.Decrypt(cipherText);

            Assert.That(decryptedText, Is.EqualTo(toEncrypt));
        }

        [Test]
        public void EncryptAndDecryptWithSmallKey()
        {
            string key = @"a";
            // create our TripleDesProvider objects with our new key
            TripleDesProvider tdes1 = new TripleDesProvider(key);
            TripleDesProvider tdes2 = new TripleDesProvider(key);

            // test encryption and decription across tdes objects
            string toEncrypt = "this is a test";
            string cipherText = tdes1.Encrypt(toEncrypt);
            string decryptedText = tdes2.Decrypt(cipherText);

            Assert.That(decryptedText, Is.EqualTo(toEncrypt));
        }

        [Test]
        public void NotFailOnLargeKey()
        {
            Assert.DoesNotThrow(() =>
            {
                TripleDesProvider tdes1 = new TripleDesProvider(@"1q2w3e4r5t6y7u8i9o0p1q2w3e4r5t6y7u8i9o0pqawsedrftgyhujikolp84hnfiusfd872349jsakmnbsdiIUBGFD*^jO)j2kjnDHKJFO9@1ml!\kj872jhbkmnsdg9835489ajikhakjdaf-+=lkjnasfkjb98jkkj2349809sifhd");
            });
        }

        [Test]
        public void NotFailOnSmallKey()
        {
            Assert.DoesNotThrow(() =>
            {
                TripleDesProvider tdes1 = new TripleDesProvider("a");
            });
        }

        [Test]
        public void NotFailOnSmallBase64Key()
        {
            Assert.DoesNotThrow(() =>
            {
                TripleDesProvider tdes1 = new TripleDesProvider("dGVzdA==");
            });
        }

        [Test]
        public void Rfc2898Test()
        {
            
            
            string key = "qawsedrftgyhujikolp121x2c345b6nb8n9mn0";
            string toHash = "hash this!";

            var hash1 = new Rfc2898DeriveBytes(toHash, Encoding.UTF8.GetBytes(key), 1000).GetBytes(24);
            var hash2 = new Rfc2898DeriveBytes(toHash, Encoding.UTF8.GetBytes(key), 1000).GetBytes(24);

            Assert.That(hash1, Is.EqualTo(hash2));

        }
    }
}
