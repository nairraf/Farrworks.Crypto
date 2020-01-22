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

        [Test]
        [TestCaseSource(typeof(EncryptDecryptTestData), "TestCases")]
        public void ComputedSeedTest(string toEncrypt)
        {
            string initialSeed = "w3ry78vnb930jsxP-5q0nG7Rp2Kl3B8";

            string[] seedParts = initialSeed.Split('-');
            SHA384CryptoServiceProvider sha = new SHA384CryptoServiceProvider();
            byte[] seedPart1 = sha.ComputeHash(Encoding.UTF8.GetBytes(seedParts[0]));
            byte[] seedPart2 = sha.ComputeHash(Encoding.UTF8.GetBytes(seedParts[1]));
            sha.Dispose();
            byte[] seedBytes = new byte[seedPart1.Length + seedPart2.Length];
            seedPart2.CopyTo(seedBytes, 0);
            seedPart1.CopyTo(seedBytes, seedPart2.Length);

            string seed1 = Convert.ToBase64String(seedBytes);

            string[] seedParts2 = initialSeed.Split('-');
            byte[] seedPart3, seedPart4;
            using (SHA384CryptoServiceProvider sha2 = new SHA384CryptoServiceProvider() )
            {
                seedPart3 = sha2.ComputeHash(Encoding.UTF8.GetBytes(seedParts[0]));
                seedPart4 = sha2.ComputeHash(Encoding.UTF8.GetBytes(seedParts[1]));
            }

            byte[] seedBytes2 = new byte[seedPart3.Length + seedPart4.Length];
            seedPart4.CopyTo(seedBytes2, 0);
            seedPart3.CopyTo(seedBytes2, seedPart4.Length);

            string seed2 = Convert.ToBase64String(seedBytes2);

            Assert.That(seed1, Is.EqualTo(seed2));

            // create our TripleDesProvider objects with our new key
            TripleDesProvider tdes1 = new TripleDesProvider(seed1);
            TripleDesProvider tdes2 = new TripleDesProvider(seed1);

            // test encryption and decription across tdes objects
            string cipherText = tdes1.Encrypt(toEncrypt);
            string decryptedText = tdes2.Decrypt(cipherText);

            Assert.That(decryptedText, Is.EqualTo(toEncrypt));
        }
    }
}
