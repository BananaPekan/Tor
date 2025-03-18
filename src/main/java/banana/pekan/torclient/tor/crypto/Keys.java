package banana.pekan.torclient.tor.crypto;

import javax.crypto.Cipher;
import java.security.MessageDigest;

public record Keys(MessageDigest digestForward, MessageDigest digestBackward, Cipher encryptionKey, Cipher decryptionKey, byte[] KH) {

    public Keys(byte[]... keys) {
        this(keys[0], keys[1], keys[2], keys[3], keys[4], false);
    }

    public Keys(byte[] digestForward, byte[] digestBackward, byte[] encryptionKey, byte[] decryptionKey, byte[] KH, boolean isHs) {
        this(
                isHs ? Cryptography.createHsDigest(digestForward) : Cryptography.createDigest(digestForward),
                isHs ? Cryptography.createHsDigest(digestBackward) : Cryptography.createDigest(digestBackward),
                Cryptography.createAesKey(Cipher.ENCRYPT_MODE, encryptionKey),
                Cryptography.createAesKey(Cipher.DECRYPT_MODE, decryptionKey),
                KH);
    }

}
