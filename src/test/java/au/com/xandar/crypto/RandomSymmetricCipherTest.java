package au.com.xandar.crypto;

import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;

/**
 * Tests RandomSymmetricCipher.
 */
public class RandomSymmetricCipherTest {

    private static final String PUBLIC_KEY_BASE64 =
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCKkC/b2fjIdS8atGeX/cOP8YWeEypeGnB1ICap\n" +
                    "dWajoUGGXWbl3410gZopmcXbN9imMmNNs7I9KsOKJj6b7PzP4/p74da55kaht0l63603iKandHAw\n" +
                    "7PeTWpHhJ3l12tAtvtiKppHqoY4IJDunOCHjB1fpmCkEX9JQ+a3vFl1/5wIDAQAB";

    private static final String PRIVATE_KEY_BASE64 =
            "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIqQL9vZ+Mh1Lxq0Z5f9w4/xhZ4T\n" +
                    "Kl4acHUgJql1ZqOhQYZdZuXfjXSBmimZxds32KYyY02zsj0qw4omPpvs/M/j+nvh1rnmRqG3SXrf\n" +
                    "rTeIpqd0cDDs95NakeEneXXa0C2+2IqmkeqhjggkO6c4IeMHV+mYKQRf0lD5re8WXX/nAgMBAAEC\n" +
                    "gYAstefrfgMr07w2Vr4SqjyfRuTBpBeIs+lTseMnzQ0ogZEeJSddx2viiytOfyL74KJUxm+KlBBQ\n" +
                    "cmsUOdD8CVVt2VcH63naa835YEVojqdj3X05IZk72LbH7eoaDDr9gL3DCOs7BdCWCJyLv93AzaZJ\n" +
                    "zLpu3d7kKEvKlL8La/SvkQJBAM+ouGIRYDD89JbZgKUnCbyHSd3VFfKOluc5/Fn4CcT8vhbrQgmA\n" +
                    "pb8rTCs7TkC4Ya66u+zB+If5CkUOe5GkjmkCQQCq0cEk+wplQIKSc6v58+k+eORgL6ld0JdiKjgi\n" +
                    "dpEMHSmtM6et6Ukhi+CWZ/oEK6O20WhOWUHqzpOCi8PponHPAkA3293FW4ExjEnK7jUBt++RjB7d\n" +
                    "kj02Iw8Kofl0xhjyqT4E8kGwRq/PLblug6R4GmEEXGzCsibFhMMzckLhGY/JAkBy4yySYL23J9Iq\n" +
                    "Cd5K+H+RYuHGx4eT721Bur+SfkhD64FSWoGWeGaVR2y//CKtl2Q+20zaFTI+aL3ReYtEodsFAkEA\n" +
                    "ooGmtWsgxDSThLn2l+gYhfZLy+hrewTWc3rvfd59Vmdvw+06d4PFM6mlwE8SJPON2uFfaztwoOFy\n" +
                    "eoxJEeDeow==";

    private final RandomSymmetricCipher cipher = new RandomSymmetricCipher();

    @Test
    public void testEncrypt() throws CryptoException {
        testEncryptDecrypt("my test data".getBytes());
        testEncryptDecrypt(new BigInteger("12345").toByteArray());
    }

    @Test
    public void testEncryptLongString() throws CryptoException {
        testEncryptDecrypt(getLongString(1000));
    }

    private byte[] getLongString(int nrBytes) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < nrBytes; i++) {
            final char chr = (char) ((i % 26) + 61); // 61 == 'a'
            sb.append(chr);
        }

        return sb.toString().getBytes();
    }

    private void testEncryptDecrypt(byte[] data) throws CryptoException {
        final CryptoPacket cryptoPacket = cipher.encrypt(data, PRIVATE_KEY_BASE64);

        System.out.println("cryptoPacket=" + cryptoPacket);

        // Convert the data into a byte array that can be readily reconstituted at the other end.
        final byte[] outputBytes = cipher.decrypt(cryptoPacket, PUBLIC_KEY_BASE64);

        Assert.assertArrayEquals(data, outputBytes);
    }
}
