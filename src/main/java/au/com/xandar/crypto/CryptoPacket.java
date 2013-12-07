package au.com.xandar.crypto;

/**
 * Represents data encrypted symmetrically along with the key used to encrypt the data
 * encrypted using an asymmetric mechanism.
 * <p/>
 * You cannot use public key cryptography to encrypt data larger than the (keySize / 8) - 11.
 * So instead you generate a random symmetric key, encrypt your data using that and then
 * encrypt the symmetric key using your public/private key and send both encrypted data
 * plus encrypted symmetric key.
 */
public final class CryptoPacket {

    private final byte[] encryptedData;
    private final byte[] encryptedSymmetricKey;
    private final byte[] symmetricCipherInitializationVector;

    public CryptoPacket(byte[] encryptedData, byte[] encryptedSymmetricKey, byte[] symmetricCipherInitializationVector) {
        this.encryptedData = encryptedData;
        this.encryptedSymmetricKey = encryptedSymmetricKey;
        this.symmetricCipherInitializationVector = symmetricCipherInitializationVector;
    }

    public byte[] getEncryptedData() {
        return encryptedData;
    }

    public byte[] getEncryptedSymmetricKey() {
        return encryptedSymmetricKey;
    }

    public byte[] getSymmetricCipherInitializationVector() {
        return symmetricCipherInitializationVector;
    }
}
