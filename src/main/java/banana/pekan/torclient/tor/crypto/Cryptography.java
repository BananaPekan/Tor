package banana.pekan.torclient.tor.crypto;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;

public class Cryptography {

    public static MessageDigest SHA1;
    public static byte SHA1_LENGTH = 20;
    public static byte SHA3_256_LENGTH = 32;
    public static byte KEY_LENGTH = 16;
    public static byte CIPHER_KEY_LENGTH = 32;
    public static byte MAC_KEY_LENGTH = 32;
    public static byte IV_LENGTH = 16;

    static {
        try {
            SHA1 = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static Keys kdfTor(byte[] X, byte[] Y) {
        int iterations = (int) Math.ceil((double) 92 / SHA1_LENGTH);
        ByteBuffer K = ByteBuffer.allocate(iterations * SHA1_LENGTH);
        byte[] K0 = Arrays.copyOf(X, X.length + Y.length + 1);
        System.arraycopy(Y, 0, K0, X.length, Y.length);

        for (byte i = 0; i < iterations; i++) {
            K0[K0.length - 1] = i;
            K.put(SHA1.digest(K0));
        }

        K.position(0);
        byte[][] keys = new byte[][]{{SHA1_LENGTH}, {SHA1_LENGTH}, {SHA1_LENGTH}, {KEY_LENGTH}, {KEY_LENGTH}};
        for (int i = 0; i < keys.length; i++) {
            keys[i] = new byte[keys[i][0]];
            K.get(keys[i]);
        }
        return new Keys(keys[1], keys[2], keys[3], keys[4], keys[0]);
    }

    public static byte[] updateDigest(MessageDigest digest, byte[] input) {
        digest.update(input);
        try {
            return ((MessageDigest) digest.clone()).digest();
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    public static MessageDigest createHsDigest(byte[] init) {
        try {
            MessageDigest sha3256 = MessageDigest.getInstance("SHA3-256");
            sha3256.update(init);
            return sha3256;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static MessageDigest createDigest(byte[] init) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(init);
            return sha1;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static Cipher createAesKey(int opmode, byte[] keyBytes) {
        try {
            Cipher key = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            key.init(opmode, keySpec, new IvParameterSpec(new byte[16]));
            return key;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    public static AsymmetricCipherKeyPair generateX25519KeyPair() {
        X25519KeyPairGenerator keyPairGenerator = new X25519KeyPairGenerator();
        keyPairGenerator.init(new X25519KeyGenerationParameters(new SecureRandom()));
        return keyPairGenerator.generateKeyPair();
    }

}
