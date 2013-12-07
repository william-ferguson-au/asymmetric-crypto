package au.com.xandar.crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.*;

/**
 * Encrypts data using a randomly generated symmetric key,
 * encrypts the symmetric key using the given public/private key
 * and returns the encrypted data and the encrypted symmetric key.
 * <p/>
 * This seemingly unnecessary double encryption is actually required
 * because RSA has a limit to the size of the data that it can encrypt.
 *
 * @see <a href="stackoverflow.com/questions/10007147/getting-a-illegalblocksizeexception-data-must-not-be-longer-than-256-bytes-when">Data must not be lolnger than 256 bytes</a>
 * @see <a href="stackoverflow.com/questions/9655920/encrypt-long-string-with-rsa-java">Encrypt long string with RSA</a>
 */
public final class RandomSymmetricCipher {

    private final static String SYMMETRIC_CIPHER = "DESede/CBC/PKCS5Padding";
    private final static String PUBLIC_KEY_CIPHER = "RSA/ECB/PKCS1Padding";

    /**
     * Encrypts data using a randomly generated symmetric key.
     *
     * The symmetric key is then encrypted using the supplied PrivateKey and
     * then entire output is collated in the returned CryptoPacket.
     *
     * @param data              Data to encrypt.
     * @param privateKeyBase64  Base64 encoded PrivateKey to sue to encrypt the symmetric key.
     * @return CryptoPacket containing the encrypted data, encrypted symmetric key and symmetric cipher IV.
     * @throws CryptoException if the data could not be encrypted.
     */
    public CryptoPacket encrypt(byte[] data, String privateKeyBase64) throws CryptoException {
        final RSAKeyPairGenerator rsaGenerator = new RSAKeyPairGenerator();
        final PrivateKey privateKey = rsaGenerator.getPrivateKeyFromBase64String(privateKeyBase64);
        return encrypt(data, privateKey);
    }

    /**
     * Encrypts data using a randomly generated symmetric key.
     *
     * The symmetric key is then encrypted using the supplied PrivateKey and
     * then entire output is collated in the returned CryptoPacket.
     *
     * @param data          Data to encrypt.
     * @param privateKey    PrivateKey to use to encrypt the randomly generated symmetric key.
     * @return CryptoPacket containing the encrypted data, encrypted symmetric key and symmetric cipher IV.
     * @throws CryptoException if the data could not be encrypted.
     */
    public CryptoPacket encrypt(byte[] data, PrivateKey privateKey) throws CryptoException {
        // Create random symmetric key
        final SymmetricKeyFactory keyFactory = new SymmetricKeyFactory();
        final SecretKey symmetricKey = keyFactory.generateRandomKey();

        // Encrypt data using the symmetric key
        final byte[] encryptedData;
        final byte[] symmetricCipherInitializationVector;
        try {
            final Cipher symmetricCipher = Cipher.getInstance(SYMMETRIC_CIPHER);
            symmetricCipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
            encryptedData = symmetricCipher.doFinal(data);
            symmetricCipherInitializationVector = symmetricCipher.getIV();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("All JVMs are required to support the '" + SYMMETRIC_CIPHER + "' cipher");
        } catch (NoSuchPaddingException e) {
            throw new IllegalStateException("All JVMs are required to support the '" + SYMMETRIC_CIPHER + "' cipher");
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("All JMs are required to support DESede keys", e);
        } catch (BadPaddingException e) {
            throw new CryptoException("Failed to encrypt data with random symmetric key", e);
        } catch (IllegalBlockSizeException e) {
            throw new CryptoException("Failed to encrypt data with random symmetric key", e);
        }

        // Encrypt the random symmetric key using the asymmetric key (NB could be a public key too).
        final Cipher rsaCipher; // asymmetric public/private key cipher
        final byte[] encryptedSymmetricKey;
        try {
            rsaCipher = Cipher.getInstance(PUBLIC_KEY_CIPHER);
            rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
            final byte[] rawSymmetricKey = keyFactory.getRawKey(symmetricKey);
            encryptedSymmetricKey = rsaCipher.doFinal(rawSymmetricKey);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("All JVMs are required to support the '" + PUBLIC_KEY_CIPHER + "' cipher");
        } catch (NoSuchPaddingException e) {
            throw new IllegalStateException("All JVMs are required to support the '" + PUBLIC_KEY_CIPHER + "' cipher");
        } catch (InvalidKeyException e) {
            throw new CryptoException("Failed to initialise public key cipher", e);
        } catch (BadPaddingException e) {
            throw new CryptoException("Failed to encrypt symmetric key", e);
        } catch (IllegalBlockSizeException e) {
            throw new CryptoException("Failed to encrypt symmetric key", e);
        }

        return new CryptoPacket(encryptedData, encryptedSymmetricKey, symmetricCipherInitializationVector);
    }


    // Decrypting

    /**
     * Decrypts a Base64 encoded CryptoPacket using a Base64 encoded PublicKey.
     *
     * @param base64EncodedPayload  Base64 encoded CryptoPacket containing the encrypted data, encrypted symmetric key and symmetric cipher IV.
     * @param publicKeyBase64       Base64 encoding of the PublicKey to use to decrypt the symmetric key.
     * @return byte array of the decrypted data.
     * @throws CryptoException if the publicKey cannot decrypt the encrypted symmetric key,
     *      or the symmetric key cannot decrypt the data,
     *      or the Base64 encoded PublicKey cannot be decoded.
     * @throws IOException if the Base64 encoded CryptoPacket cannot be converted to a CryptoPacket.
     */
    public byte[] decrypt(String base64EncodedPayload, String publicKeyBase64) throws CryptoException, IOException {
        // Convert Base64EncodedPayload into CryptoPacket
        final CryptoPacketConverter cryptoPacketConverter = new CryptoPacketConverter();
        final CryptoPacket cryptoPacket = cryptoPacketConverter.convert(base64EncodedPayload);
        return decrypt(cryptoPacket, publicKeyBase64);
    }

    /**
     * Decrypts a CryptoPacket using a Base64 encoded PublicKey.
     *
     * @param cryptoPacket           CryptoPacket containing the encrypted data, encrypted symmetric key and symmetric cipher IV.
     * @param publicKeyBase64   Base64 encoding of the PublicKey to use to decrypt the symmetric key.
     * @return byte array of the decrypted data.
     * @throws CryptoException if the publicKey cannot decrypt the encrypted symmetric key,
     *      or the symmetric key cannot decrypt the data,
     *      or the Base64 encoded PublicKey cannot be decoded.
     */
    public byte[] decrypt(CryptoPacket cryptoPacket, String publicKeyBase64) throws CryptoException {
        // Decrypt cryptoPacket#encryptedSymmetricKey using asymmetricKey
        final RSAKeyPairGenerator rsaGenerator = new RSAKeyPairGenerator();
        final PublicKey publicKey = rsaGenerator.getPublicKeyFromBase64String(publicKeyBase64);
        return decrypt(cryptoPacket, publicKey);
    }

    // This is the alpha method because of the string typing.

    /**
     * Decrypts a CryptoPacket using a PublicKey.
     *
     * @param cryptoPacket       CryptoPacket containing the encrypted data, encrypted symmetric key and symmetric cipher IV.
     * @param publicKey     PublicKey to use to decrypt the encrypted symmetric key.
     * @return byte array of the decrypted data.
     * @throws CryptoException if the publicKey cannot decrypt the encrypted symmetric key, or the symmetric key cannot decrypt the data.
     */
    public byte[] decrypt(CryptoPacket cryptoPacket, PublicKey publicKey) throws CryptoException {
        // Decrypt cryptoPacket#encryptedSymmetricKey using asymmetricKey
        final SecretKey symmetricKey;
        try {
            // asymmetric public/private key cipher
            final Cipher rsaCipher = Cipher.getInstance(PUBLIC_KEY_CIPHER);
            rsaCipher.init(Cipher.DECRYPT_MODE, publicKey);
            final byte[] rawSymmetricKey = rsaCipher.doFinal(cryptoPacket.getEncryptedSymmetricKey());

            final SymmetricKeyFactory keyFactory = new SymmetricKeyFactory();
            symmetricKey = keyFactory.generateKey(rawSymmetricKey);

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("All JVMs are required to support the '" + PUBLIC_KEY_CIPHER + "' cipher");
        } catch (NoSuchPaddingException e) {
            throw new IllegalStateException("All JVMs are required to support the '" + PUBLIC_KEY_CIPHER + "' cipher");
        } catch (InvalidKeyException e) {
            throw new CryptoException("Failed to initialise cipher", e);
        } catch (BadPaddingException e) {
            throw new CryptoException("Failed to decrypt symmetric key", e);
        } catch (IllegalBlockSizeException e) {
            throw new CryptoException("Failed to decrypt symmetric key", e);
        }

        // Decrypt cryptoPacket#encryptedData using symmetricKey
        try {
            final Cipher symmetricCipher = Cipher.getInstance(SYMMETRIC_CIPHER);
            final IvParameterSpec ivParameterSpec = new IvParameterSpec(cryptoPacket.getSymmetricCipherInitializationVector());
            symmetricCipher.init(Cipher.DECRYPT_MODE, symmetricKey, ivParameterSpec);
            return symmetricCipher.doFinal(cryptoPacket.getEncryptedData());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("All JVMs are required to support the '" + SYMMETRIC_CIPHER + "' cipher");
        } catch (NoSuchPaddingException e) {
            throw new IllegalStateException("All JVMs are required to support the '" + SYMMETRIC_CIPHER + "' cipher");
        } catch (IllegalBlockSizeException e) {
            throw new CryptoException("Failed to decrypt data", e);
        } catch (BadPaddingException e) {
            throw new CryptoException("Failed to decrypt data", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CryptoException("Failed to initialise cipher", e);
        } catch (InvalidKeyException e) {
            throw new CryptoException("Failed to initialise cipher", e);
        }
    }
}
