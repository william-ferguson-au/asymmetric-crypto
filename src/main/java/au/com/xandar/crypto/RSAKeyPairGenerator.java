package au.com.xandar.crypto;

import org.apache.commons.codec.binary.Base64;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Generates a public/private key pair.
 */
public class RSAKeyPairGenerator {

    private static final String KEY_PAIR_GENERATION_ALGORITHM = "RSA";

    private final KeyFactory keyFactory;
    private final KeyPairGenerator keyPairGenerator;
    private final Base64 base64 = new Base64(76);

    public RSAKeyPairGenerator() {
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(KEY_PAIR_GENERATION_ALGORITHM);
            keyFactory = KeyFactory.getInstance(KEY_PAIR_GENERATION_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("All JVMs are required to support the RSA algorithm", e);
        }
    }

    public RSAKeyPair generate() {
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();
        final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        final byte[] publicKeyEncoded = base64.encode(publicKey.getEncoded());
        final String publicKeyString = new String(publicKeyEncoded);

        final byte[] privateKeyEncoded = base64.encode(privateKey.getEncoded());
        final String privateKeyString = new String(privateKeyEncoded);

        return new RSAKeyPair(privateKeyString, publicKeyString);
    }

    /**
     * @param base64String Base64 representation of the PublicKey.
     * @return PublicKey that can be used to encode/decode a message for a source for whom you have the PublicKey.
     * @throws CryptoException if the base64String could not be translated into a PublicKey.
     */
    public PublicKey getPublicKeyFromBase64String(String base64String) throws CryptoException {
        try {
            final byte[] publicKeyDecoded = base64.decode(base64String);
            final KeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyDecoded);
            return keyFactory.generatePublic(publicKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new CryptoException("Failed to generate public key", e);
        }
    }

    /**
     * @param base64String Base64 representation of the PrivateKey.
     * @return PrivateKey that can be used to encode/decode a message for a source that has your PublicKey.
     * @throws CryptoException if the base64String could not be translated into a PrivateKey.
     */
    public PrivateKey getPrivateKeyFromBase64String(String base64String) throws CryptoException {
        try {
            final byte[] privateKeyDecoded = base64.decode(base64String);
            final KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyDecoded);
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new CryptoException("Failed to generate private key", e);
        }
    }



    public static void main(String[] args) throws CryptoException {
        final RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        final RSAKeyPair keyPair = generator.generate();
        System.out.println("PublicKey-Base64=" + keyPair.getBase64PublicKey());
        System.out.println("PrivateKey-Base64=" + keyPair.getBase64PrivateKey());

        final PublicKey publicKey = generator.getPublicKeyFromBase64String(keyPair.getBase64PublicKey());
        final PrivateKey privateKey = generator.getPrivateKeyFromBase64String(keyPair.getBase64PrivateKey());
        System.out.println("PublicKey=" + publicKey);
        System.out.println("PrivateKey=" + privateKey);
    }
}
