package au.com.xandar.crypto;

import java.util.Arrays;

/**
 * Represents data encrypted symmetrically along with the key used to encrypt the data
 * encrypted using an asymmetric mechanism.
 * <p/>
 * You cannot use public key cryptography to encrypt data larger than the (keySize / 8) - 11.
 * <p/>
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

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof CryptoPacket)) {
            return false;
        }

        CryptoPacket that = (CryptoPacket) o;

        if (!Arrays.equals(encryptedData, that.encryptedData)) {
            return false;
        }
        if (!Arrays.equals(encryptedSymmetricKey, that.encryptedSymmetricKey)) {
            return false;
        }
        if (!Arrays.equals(symmetricCipherInitializationVector, that.symmetricCipherInitializationVector)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(encryptedData);
        result = 31 * result + Arrays.hashCode(encryptedSymmetricKey);
        result = 31 * result + Arrays.hashCode(symmetricCipherInitializationVector);
        return result;
    }

    @Override
    public String toString() {
        return "CryptoPacket{" +
            "\n encryptedData=" + toReadableOutput("                ", encryptedData) +
            ",\n encryptedSymmetricKey=" + toReadableOutput("                ", encryptedSymmetricKey) +
            ",\n symmetricCipherInitializationVector=" + toReadableOutput("                ", symmetricCipherInitializationVector) +
            "\n}";
    }

    private String toReadableOutput(String prepend, byte[] data) {
        final StringBuilder sb = new StringBuilder();
        int i = 0;
        sb.append('[');
        for (byte ch : data) {
            if (sb.length() > 1) {
                sb.append(", ");
            }
            if (i % 26 == 25) {
                sb.append('\n'); // Wrap every 26 bytes
                sb.append(prepend);
            }
            sb.append(ch);
            i++;
        }
        sb.append(']');
        return sb.toString();
    }
}
