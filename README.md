# Farrworks.Crypto

Reusable Crypto objects for very basic cryptography needs.

The objects in this library should not be used to encrypt highly sensitive data. Their purpose is to have an easy way to reasonably protect text based data for a variety of purposes. There are issues with the below methods, this is really only meant to not have clear text passwords in databases/configuration files. Instead what is stored is an initial seed value, and encrypted cipherText. Both together will not allow you to decrypt the cipherText. You must know the transformation process which converts the initial seed to the real seed, which is then transformed by TripleDesProvider() to the real key that is used for encyprtion and decryption. If that transformation process is known, and  you have access to the initial seed and the cipher text that was encypted through the initial seed, then decryption will be possible.

## Available Namespaces

Farrworks.Crypto.Basic

- TripleDesProvider(string seed)
  - Encrypts strings using 3DES-CBC and a random initialization vector (IV) every time you encrypt something. This way encrypting the same string produces cipherText that continously changes with little to no repeating patterns.
  - The key's that are produced (with any length of seed) are 192bits in length, the maximum for 3DES. A transformation process is used against the seed to generate the key. The same seed will always generate the same key, so take the appropriate action to protect the seed. It is recommended to not have this seed directly in a config file/DB, but come up with another means of generating the seed on your own, using your own custom transformation process. This way you can persist the initial seed on disk (file/DB/etc.), but once you read it in, you transform it to the actual seed that you will use. Here is a basic idea, but you should try and come up with something different on your own:

    ````c#
    // get the initial seed from somewhere - this can read in from some file,
    // specified in a configuration setting, read from a DB, etc..
    // do not use this seed/process, this is just an idea on how to generate
    // somehting more complex from an initial seed:
    string initialSeed = "w3ry78vnb930jsxP+5q0nG7Rp2Kl3B8";

    // do some custom transformation on it to create a more complex seed to pass to TripleDesProvider()
    // we split our inititial Seed into two parts, using the '+' as a seperator
    // we then sha384 hash each part seperately. and glue both hashes together in reverse order
    // we then convert it to a Base64 string
    string[] seedParts = initialSeed.Split('+');
    string[] seedParts2 = initialSeed.Split('+');
    byte[] seedPart1, seedPart2;
    using (SHA384CryptoServiceProvider sha = new SHA384CryptoServiceProvider() )
    {
        seedPart1 = sha.ComputeHash(Encoding.UTF8.GetBytes(seedParts[0]));
        seedPart2 = sha.ComputeHash(Encoding.UTF8.GetBytes(seedParts[1]));
    }
    byte[] seedBytes = new byte[seedPart1.Length + seedPart2.Length];
    seedPart2.CopyTo(seedBytes, 0);
    seedPart1.CopyTo(seedBytes, seedPart2.Length);
    string seed = Convert.ToBase64String(seedBytes);

    // this produces a string like:
    //      BZ6t+c9mj68sRcVlEQIybYLqnpVx+IN5D5vSOf+Vf8FNkbsFpr1T4KESQsHRgVRSEEtu77KC0lXiR/FI1XzscsSI4XkmULW2npq6te9pljFkfqAleG9Sg9SgVpb2ALpD
    //
    // Something like this will always produce the same string, so the above value will always be
    // generated from this specific initialSeed value and process.
    // The custom transformation process that you come up with will help keep the computed seed secret,
    // so persisting the initialSeed on disk somewhere is a little less risky, as the attacker will need to
    // figure out your custom transformation process which generates the real seed that is used during the
    // encryption process.
    //
    // we can use as our computed seed and pass it to TripleDesProvider().
    // TripleDesProvider will do it's own basic transformation process on the seed
    // but it is not a secret, as it's published here.
    // This is why you should come up with your own custom transformation process.
    TripleDesProvider tdes = new TripleDesProvider(seed);
    ````

  - Example Use Case:

    ````c#
    using Farrworks.Crypto.Basic;

    // import your secret key somehow
    string seed = "change me - see above example for something more complex";


    // somewhere else
    // our data we want to protect
    string sensitiveData = "protect me";
    TripleDesProvider tdes = new TripleDesProvider(seed);

    string cipherText = tdes.Encrypt(sensitiveData);

    // store the cipherText somewhere, like in a file, or database cell 

    // at a later date, when you need to decrypt the cipherText
    // you must use the exact same secret key that was used to
    // initially encrypt the data
    string seed = "change me - see above example for something more complex";

    // get our cipher text somehow (read from a database cell/file etc.)
    TripleDesProvider tdes = new TripleDesProvider(seed);
    string clearText = tdes.Decrypt(cipherText);
    ````

See unit tests for more examples if you want.
