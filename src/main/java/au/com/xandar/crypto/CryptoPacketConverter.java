package au.com.xandar.crypto;

import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

/**
 * Responsible for converting a CryptoPacket into a Base64 String and vice versa.
 */
public final class CryptoPacketConverter {

    private final Base64 base64 = new Base64();

    /**
     * Converts a CryptoPacket into a Base64 encoded String.
     */
    public String convert(CryptoPacket cryptoPacket) throws CryptoException {
        final ByteArrayOutputStream stream = new ByteArrayOutputStream();

        try {
            final DataOutputStream dataOutputStream = new DataOutputStream(stream);
            dataOutputStream.writeInt(cryptoPacket.getEncryptedData().length);
            dataOutputStream.write(cryptoPacket.getEncryptedData());
            dataOutputStream.writeInt(cryptoPacket.getEncryptedSymmetricKey().length);
            dataOutputStream.write(cryptoPacket.getEncryptedSymmetricKey());
            dataOutputStream.writeInt(cryptoPacket.getSymmetricCipherInitializationVector().length);
            dataOutputStream.write(cryptoPacket.getSymmetricCipherInitializationVector());
        } catch (IOException e) {
            // This is highly unlikely to occur, if not impossible.
            throw new CryptoException("Cannot convert CryptoPacket into a Base64 String", e);
        }

        final byte[] payload = stream.toByteArray();
        final byte[] base64Payload = base64.encode(payload);

        try {
            return new String(base64Payload, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            // UTF-8 should always be supported.
            throw new CryptoException("Could not encode Base64 String", e);
        }
    }

    /**
     * Converts a Base64 encoded String into a CryptoPacket.
     */
    public CryptoPacket convert(final String base64Payload) throws CryptoException {
        final byte[] payloadBytes;
        try {
            final byte[] base64PayloadBytes = base64Payload.getBytes("UTF-8");
            payloadBytes = base64.decode(base64PayloadBytes);
        } catch (UnsupportedEncodingException e) {
            // UTF-8 should always be supported.
            throw new CryptoException("Could not decode Base64 String", e);
        }

        final DataInputStream stream = new DataInputStream(new ByteArrayInputStream(payloadBytes));
        final byte[] encryptedData = readByteArray(stream);
        final byte[] encryptedSymmetricKey = readByteArray(stream);
        final byte[] symmetricCipherIV = readByteArray(stream);

        return new CryptoPacket(encryptedData, encryptedSymmetricKey, symmetricCipherIV);
    }

    private byte[] readByteArray(DataInputStream stream) throws CryptoException {
        final int length;
        try {
            length = stream.readInt();
            if (length < 0) {
                throw new CryptoException("Byte array cannot be parsed - does not represent a CryptoPacketPayload");
            }
        } catch (IOException e) {
            throw new CryptoException("Byte array does not contain a length - does not represent a CryptoPacketPayload");
        }

        final byte[] bytes = new byte[length];
        final int nrBytesRead;
        try {
            nrBytesRead = stream.read(bytes);
            if (length != nrBytesRead) {
                throw new CryptoException("Invalid Base64 String. Expected " + length + " bytes but only found " + nrBytesRead);
            }
        } catch (IOException e) {
            throw new CryptoException("Invalid Base64 String. Cannot convert Base64 String into a CryptoPacket");
        }
        return bytes;
    }
}
