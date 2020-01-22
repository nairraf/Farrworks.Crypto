using System;
using NUnit.Framework;
using Farrworks.Crypto.Basic;
using System.Security.Cryptography;
using System.Text;
using Farrworks.Crypto.Tests.Data;

namespace Farrworks.Crypto.Tests
{
   
    public class Basic_TrippleDesProvider_Should
    {
        [Test]
        [TestCaseSource(typeof(EncryptDecryptTestData), "TestCases")]
        public void EncryptAndDecrypt(string toEncrypt)
        {
            // generate a new random 192bit symetric key
            TripleDESCryptoServiceProvider csp = new TripleDESCryptoServiceProvider();
            csp.GenerateKey();
            string key = Convert.ToBase64String(csp.Key);
            
            // create our TripleDesProvider objects with our new key
            TripleDesProvider tdes1 = new TripleDesProvider(key);
            TripleDesProvider tdes2 = new TripleDesProvider(key);

            // test encryption and decription across tdes objects
            string cipherText = tdes1.Encrypt(toEncrypt);
            string decryptedText = tdes2.Decrypt(cipherText);

            Assert.That(decryptedText, Is.EqualTo(toEncrypt));
        }

        [Test]
        [TestCaseSource(typeof(EncryptDecryptTestData), "TestCases")]
        public void EncryptAndDecryptWithLargeKey(string toEncrypt)
        {
            string key = @"1q2w3e4r5t6y7u8i9o0p1q2w3e4r5t6y7u8i9o0pqawsedrftgyhujikolp84hnfiusfd872349jsakmnbsdiIUBGFD*^jO)j2kjnDHKJFO9@1ml!\kj872jhbkmnsdg9835489ajikhakjdaf-+=lkjnasfkjb98jkkj2349809sifhd";
            // create our TripleDesProvider objects with our new key
            TripleDesProvider tdes1 = new TripleDesProvider(key);
            TripleDesProvider tdes2 = new TripleDesProvider(key);

            // test encryption and decription across tdes objects
            string cipherText = tdes1.Encrypt(toEncrypt);
            string decryptedText = tdes2.Decrypt(cipherText);

            Assert.That(decryptedText, Is.EqualTo(toEncrypt));
        }

        [Test]
        [TestCaseSource(typeof(EncryptDecryptTestData), "TestCases")]
        public void EncryptAndDecryptWithSmallKey(string toEncrypt)
        {
            string key = @"a";
            // create our TripleDesProvider objects with our new key
            TripleDesProvider tdes1 = new TripleDesProvider(key);
            TripleDesProvider tdes2 = new TripleDesProvider(key);

            // test encryption and decription across tdes objects
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
        public void DecryptFromStoredCipherText()
        {
            TripleDesProvider tdes = new TripleDesProvider("123456");
            string toEncrypt = "thisIsMyPassword";
            string decrypt = tdes.Decrypt(@"kZzVRyF63d26JwCYGDu5YO+GfYus8vOy6//Cabdxnkv");

            Assert.That(decrypt, Is.EqualTo(toEncrypt));
        }
    }
}
