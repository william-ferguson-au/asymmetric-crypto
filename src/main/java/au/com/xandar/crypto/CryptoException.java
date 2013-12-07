/*
 * Copyright (c) Xandar IP 2013.
 * All Rights Reserved
 * No part of this application may be reproduced, copied, modified or adapted, without the prior written consent
 * of the author, unless otherwise indicated for stand-alone materials.
 *
 * Contact support@xandar.com.au for copyright requests.
 */

package au.com.xandar.crypto;

/**
 * Indicates there was a problem during encryption or decryption.
 */
public final class CryptoException extends Exception {

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
