package banana.pekan.torclient.tor.crypto;

import javax.crypto.Cipher;
import java.security.MessageDigest;

public record Keys(MessageDigest digestForward, MessageDigest digestBackward, Cipher encryptionKey, Cipher decryptionKey, byte[] KH) {

    public Keys(byte[]... keys) {
        this(keys[0], keys[1], keys[2], keys[3], keys[4]);
    }

    Keys(byte[] digestForward, byte[] digestBackward, byte[] encryptionKey, byte[] decryptionKey, byte[] KH) {
        this(Cryptography.createDigest(digestForward),
                Cryptography.createDigest(digestBackward),
                Cryptography.createAesKey(Cipher.ENCRYPT_MODE, encryptionKey),
                Cryptography.createAesKey(Cipher.DECRYPT_MODE, decryptionKey),
                KH);
    }

}
