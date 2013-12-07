package au.com.xandar.crypto;

/**
 * Represents the Base64 stringified values of an RSA Public Key Pair.
 */
public class RSAKeyPair {

    private final String privateKeyString;
    private final String publicKeyString;

    public RSAKeyPair(String privateKeyString, String publicKeyString) {
        this.privateKeyString = privateKeyString;
        this.publicKeyString = publicKeyString;
    }

    public String getBase64PrivateKey() {
        return privateKeyString;
    }

    public String getBase64PublicKey() {
        return publicKeyString;
    }
}
