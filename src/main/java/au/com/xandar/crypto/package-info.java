/**
 * The classes in this package provide a mechanism to easily encrypt/decrypt data using public/private keys.
 * <p>
 * Public/private cryptography has a limit to the size of the data that it can encrypt.
 * The limit is keySize (in bits) / 8 - 11.
 * </p>
 * <p>
 * This is problematic because the amount of data to be encrypted is variable. In order to overcome this limitation
 * standard practice is to generate a random symmetric key, use that to encrypt all of your data, then encrypt the
 * symmetric key using the private key and transmit the encrypted data and encrypted symmetric key.
 * </p>
 * The core of the package is the {@link au.com.xandar.crypto.AsymmetricCipher} class. The general usage is like so:
 * <pre>
 * {@code
 * final RandomSymmetricCipher cipher = new RandomSymmetricCipher();
 *
 * // Encrypt the data and the random symmetric key.
 * final CryptoPacket cryptoPacket = cipher.encrypt(inputData, PRIVATE_KEY_BASE64);
 *
 * // Convert the CryptoPacket into a Base64 String that can be readily reconstituted at the other end.
 * final CryptoPacketConverter cryptoPacketConverter = new CryptoPacketConverter();
 * final String base64EncryptedData = cryptoPacketConverter.convert(cryptoPacket);
 *
 * System.out.println("Base64EncryptedData=" + base64EncryptedData);
 *
 * // Decrypt the Base64 encoded (and encrypted) String.
 * final byte[] outputData = cipher.decrypt(base64EncryptedData, PUBLIC_KEY_BASE64);
 * }
 * </pre>
 *
 * <p>
 * </p>
 *
 * @see <a href="stackoverflow.com/questions/10007147/getting-a-illegalblocksizeexception-data-must-not-be-longer-than-256-bytes-when">Data must not be lolnger than 256 bytes</a>
 * @see <a href="stackoverflow.com/questions/9655920/encrypt-long-string-with-rsa-java">Encrypt long string with RSA</a>
 *
 */
package au.com.xandar.crypto;
