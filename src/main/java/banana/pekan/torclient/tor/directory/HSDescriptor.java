package banana.pekan.torclient.tor.directory;

import banana.pekan.torclient.tor.crypto.Cryptography;
import org.bouncycastle.crypto.digests.SHAKEDigest;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HSDescriptor {

    static MessageDigest SHA3_256;

    static {
        try {
            SHA3_256 = MessageDigest.getInstance("SHA3-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] getCredential(byte[] hsPublicKey) {
        // N_hs_cred = SHA3_256("credential" | public-identity-key);
        SHA3_256.update("credential".getBytes());
        SHA3_256.update(hsPublicKey);
        return SHA3_256.digest();
    }

    private static byte[] deriveSubCredential(byte[] credential, byte[] hsBlindedPublicKey) {
        // N_hs_subcred = SHA3_256("subcredential" | N_hs_cred | blinded-public-key).
        SHA3_256.update("subcredential".getBytes());
        SHA3_256.update(credential);
        SHA3_256.update(hsBlindedPublicKey);
        return SHA3_256.digest();
    }

    // WIP
    public static void parseDirect(byte[] superencrypted, long revision, byte[] hsPublicKey, byte[] hsBlindedPublicKey) throws NoSuchAlgorithmException {
        byte[] credential = getCredential(hsPublicKey);
        byte[] subcredential = deriveSubCredential(credential, hsBlindedPublicKey);

        // secret_input = SECRET_DATA | N_hs_subcred | INT_8(revision_counter)
        // In this case, SECRET_DATA is the hidden service's blinded public key.
        SHAKEDigest shakeDigest = new SHAKEDigest(256);
        shakeDigest.update(hsBlindedPublicKey, 0, hsBlindedPublicKey.length);
        shakeDigest.update(subcredential, 0, subcredential.length);
        shakeDigest.update(ByteBuffer.allocate(8).putLong(revision).array(), 0, 8);

        // keys = SHAKE256_KDF(secret_input | salt | STRING_CONSTANT, S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN)
        byte[] salt = new byte[16];
        System.arraycopy(superencrypted, 0, salt, 0, salt.length);
        byte[] mac = new byte[32];
        int ciphertextLength = superencrypted.length - salt.length - mac.length;
        byte[] ciphertext = new byte[ciphertextLength];
        System.arraycopy(superencrypted, salt.length, ciphertext, 0, ciphertextLength);
        System.arraycopy(superencrypted, salt.length + ciphertextLength, mac, 0, mac.length);
        shakeDigest.update(salt, 0, salt.length);
        String STRING_CONSTANT = "hsdir-superencrypted-data";
        shakeDigest.update(STRING_CONSTANT.getBytes(), 0, STRING_CONSTANT.length());

//       SECRET_KEY = first S_KEY_LEN bytes of keys
//       SECRET_IV  = next S_IV_LEN bytes of keys
//       MAC_KEY    = last MAC_KEY_LEN bytes of keys
        byte[] keys = new byte[Cryptography.MAC_KEY_LENGTH + Cryptography.CIPHER_KEY_LENGTH + Cryptography.IV_LENGTH];
        shakeDigest.doOutput(keys, 0, keys.length);

        byte[] secretKey = new byte[Cryptography.CIPHER_KEY_LENGTH];
        byte[] secretIv = new byte[Cryptography.IV_LENGTH];
        byte[] macKey = new byte[Cryptography.MAC_KEY_LENGTH];
        System.arraycopy(keys, 0, secretKey, 0, secretKey.length);
        System.arraycopy(keys, secretKey.length, secretIv, 0, secretIv.length);
        System.arraycopy(keys, secretKey.length + secretIv.length, macKey, 0, macKey.length);

        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(secretKey, "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(secretIv));
            byte[] decrypted = cipher.update(ciphertext);
            System.out.println(new String(decrypted));
        } catch (NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

}
