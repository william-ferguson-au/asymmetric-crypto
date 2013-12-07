/*
 * Copyright (c) Xandar IP 2013.
 * All Rights Reserved
 * No part of this application may be reproduced, copied, modified or adapted, without the prior written consent
 * of the author, unless otherwise indicated for stand-alone materials.
 *
 * Contact support@xandar.com.au for copyright requests.
 */

package au.com.xandar.crypto;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * Generates a randomly generated symmetric (DESede) key.
 */
public final class SymmetricKeyFactory {

    private final static String KEY_GEN_ALGORITHM = "DESede";

    private final SecureRandom random = new SecureRandom();

    public SecretKey generateRandomKey() {
        try {
            final byte[] rawKey = new byte[24];
            random.nextBytes(rawKey);
            return generateKey(rawKey);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("DESedeKey should be able to handle 24 random bytes", e);
        }
    }

    public SecretKey generateKey(byte[] rawKey) throws InvalidKeyException {
        final DESedeKeySpec keyspec = new DESedeKeySpec(rawKey);
        try {
            final SecretKeyFactory keyfactory = SecretKeyFactory.getInstance(KEY_GEN_ALGORITHM);
            return keyfactory.generateSecret(keyspec);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JVM is required to support '" + KEY_GEN_ALGORITHM + "' key generation algorithm", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("JVM is required to support DESedeKeySpec", e);
        }
    }

    public byte[] getRawKey(SecretKey key) {
        try {
            final SecretKeyFactory keyfactory = SecretKeyFactory.getInstance(KEY_GEN_ALGORITHM);
            final DESedeKeySpec keyspec = (DESedeKeySpec) keyfactory.getKeySpec(key, DESedeKeySpec.class);
            return keyspec.getKey();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JVM is required to support '" + KEY_GEN_ALGORITHM + "' key generation algorithm", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("JVM is required to support DESedeKeySpec", e);
        }
    }
}
