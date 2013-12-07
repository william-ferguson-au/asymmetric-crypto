/*
 * Copyright (c) Xandar IP 2013.
 * All Rights Reserved
 * No part of this application may be reproduced, copied, modified or adapted, without the prior written consent
 * of the author, unless otherwise indicated for stand-alone materials.
 *
 * Contact support@xandar.com.au for copyright requests.
 */

package au.com.xandar.crypto;

import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Responsible for converting a CryptoPacket into a Base64 String and vice versa.
 */
public final class CryptoPacketConverter {

    private final Base64 base64 = new Base64();

    public String convert(CryptoPacket cryptoPacket) throws IOException {
        final ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(cryptoPacket.getEncryptedData().length);
        stream.write(cryptoPacket.getEncryptedData());
        stream.write(cryptoPacket.getEncryptedSymmetricKey().length);
        stream.write(cryptoPacket.getEncryptedSymmetricKey());
        stream.write(cryptoPacket.getSymmetricCipherInitializationVector().length);
        stream.write(cryptoPacket.getSymmetricCipherInitializationVector());

        final byte[] jsonPayload = stream.toByteArray();
        final byte[] base64Payload = base64.encode(jsonPayload);

        return new String(base64Payload);
    }

    public CryptoPacket convert(String base64Payload) throws IOException {
        final byte[] payloadBytes = base64.decode(base64Payload.getBytes());

        final ByteArrayInputStream stream = new ByteArrayInputStream(payloadBytes);
        final byte[] encryptedData = readByteArray(stream);
        final byte[] encryptedSymmetricKey = readByteArray(stream);
        final byte[] symmetricCipherIV = readByteArray(stream);

        return new CryptoPacket(encryptedData, encryptedSymmetricKey, symmetricCipherIV);
    }

    private byte[] readByteArray(ByteArrayInputStream stream) throws IOException {
        final int length = stream.read();
        final byte[] bytes = new byte[length];
        final int nrBytesRead = stream.read(bytes);
        if (length != nrBytesRead) {
            throw new IOException("ReadError : expected " + length + " bytes but only found " + nrBytesRead);
        }
        return bytes;
    }
}
