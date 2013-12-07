random-symmetric-crypto
=======================

Provides a very simple library that uses public key crypto
to encrypt any size data using a randomly generated symmetric key.

This library lets you boil the code down to about 3 lines on the client and 3 lines on the server.


   final RandomSymmetricCipher cipher = new RandomSymmetricCipher();
 
   // Encrypt the data and the random symmetric key.
   final CryptoPacket cryptoPacket = cipher.encrypt(inputData, PRIVATE_KEY_BASE64);
 
   // Convert the CryptoPacket into a Base64 String that can be readily reconstituted at the other end.
   final CryptoPacketConverter cryptoPacketConverter = new CryptoPacketConverter();
   final String base64EncryptedData = cryptoPacketConverter.convert(cryptoPacket);
 
   // Decrypt the Base64 encoded (and encrypted) String.
   final byte[] outputData = cipher.decrypt(base64EncryptedData, PUBLIC_KEY_BASE64);
