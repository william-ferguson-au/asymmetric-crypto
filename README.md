random-symmetric-crypto
=======================

Provides a very simple library that uses public key crypto
to encrypt any size data using a randomly generated symmetric key.

You may know that public key cryptography can be used to encrypt/decrypt data without the 2 parties involved sharing a key with one another. What you may not realise is that it is not logistically possible to encrypt data *directly* using public key cryptography as you can only encrypt data that is shorter than the length of the key. NB public keys are rarely longer than 2048 bits since fabrication and usage costs increase with key size and 2048 bit keys are considered safe (uncrackable) up until 2030.

How does PK cryptography work?
==============================

Essentially it allows you to *randomly* select a *symmetric* key up to the length of your partner's PK. You can use that random symmetric key to encrypt any amount of data. Since your random symmetric key is shorter than the PK, the PK is able to to encrypt your random symmetric key. Then send your partner the encrypted data and the encrypted random-symmetric key.

Your partner can use their private key to decode the encrypted key. And then use the decrypted random-symmetric key to decrypted the data.

Voila, encryption with no prior key sharing.

Verifying the Sender
====================
For added security, you can sign the message so that your partner can confirm that you sent it. Just take your payload (encrypted data + encrypted random-symmetric-key) and repeat the encryption process but this time use *your* private key. Your partner can then first decrypt it using your public key which will confirm it came from you, and then decrypot using their private key to find out whyat you sent them.


Example
=======

This library lets you boil the code down to about 4 lines on the client and 2 lines on the server.

Local:

    final RandomSymmetricCipher cipher = new RandomSymmetricCipher();
 
    // Generate a random symmetric key, use it to encrypt the data,  encrypt the random key using the private key 
    // and return a CryptoPacket containing the encrypted data and the encrypted random key.
    final CryptoPacket cryptoPacket = cipher.encrypt(inputData, PUBLIC_KEY_BASE64);
 
    // Convert the CryptoPacket into a Base64 String that can be readily reconstituted at the other end.
    final CryptoPacketConverter cryptoPacketConverter = new CryptoPacketConverter();
    final String base64EncryptedData = cryptoPacketConverter.convert(cryptoPacket);


Remote:

    final RandomSymmetricCipher cipher = new RandomSymmetricCipher();

    // Convert the Base64 encoded String into a CryptoPacket, decode the random-symmetric key using the public key,
    // decode the data using the random-symmetric key and return the decoded data.
    final byte[] outputData = cipher.decrypt(base64EncryptedData, PRIVATE_KEY_BASE64);
