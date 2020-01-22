# Farrworks.Crypto
Reusable Crypto objects for very basic cryptography needs. 

The objects in this library should not be used to encrypt highly sensitive data. Their purpose is to have an easy way to reasonably protect text based data for a variety of purposes.

## Available Namespaces

Farrworks.Crypto.Basic

 - TripleDesProvider(string key) 
    - Encrypts strings using 3DES-CBC and a random initialization vector (IV) every time you encrypt something. This way encrypting the same string produces cipherText that continously changes with little to no repeating patterns.
    - The key's that are produced with any length of a secret key are 192bits in length, the maximum for 3DES.
    - Example Use Case:
        ````c#
        using Farrworks.Crypto.Basic;
        
        // import your secret key somehow
        string key = "change me";
        

        // somewhere else
        // our data we want to protect
        string sensitiveData = "protect me";
        TripleDesProvider tdes = new TripleDesProvider(key);
        
        string cipherText = tdes.Encrypt(sensitiveData);

        // store the cipherText somewhere, like in a file, or database cell 

        // at a later date, when you need to decrypt the cipherText
        // you must use the exact same secret key that was used to
        // initially encrypt the data
        string key = "change me";

        // get our cipher text somehow (read from a database cell/file etc.)
        TripleDesProvider tdes = new TripleDesProvider(key);
        string clearText = tdes.Decrypt(cipherText);
        ````
    - see unit tests for more examples
