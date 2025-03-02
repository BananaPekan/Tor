package banana.pekan.torclient.tor;

import banana.pekan.torclient.tor.crypto.Keys;
import banana.pekan.torclient.tor.directory.RelayProperties;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static banana.pekan.torclient.tor.crypto.Cryptography.*;

public class Handshake {

    public static final byte[] NTOR_PROTOID = "ntor-curve25519-sha256-1".getBytes();

    private static byte[] createNtorHandshake(RelayProperties properties, X25519PublicKeyParameters publicKey) {
        ByteBuffer buffer = ByteBuffer.allocate(84);
        buffer.put(properties.fingerprint());
        buffer.put(properties.ntorOnionKey());
        // temporary public key (32 bytes, curve25519)
        buffer.put(publicKey.getEncoded());
        return buffer.array();
    }

    public static byte[] createNtorBlock(RelayProperties properties, X25519PublicKeyParameters publicKey) {
        byte[] handshake = createNtorHandshake(properties, publicKey);
        ByteBuffer buffer = ByteBuffer.allocate(4 + handshake.length);
        buffer.put((byte) 0x00);
        buffer.put((byte) 0x02);
        buffer.putShort((short) handshake.length);
        buffer.put(handshake);
        return buffer.array();
    }

    public static byte[] calculateSharedSecret(X25519PrivateKeyParameters privateKey, X25519PublicKeyParameters publicKey) {
        byte[] secret = new byte[32];
        privateKey.generateSecret(publicKey, secret, 0);
        return secret;
    }

    public static byte[] hmac(byte[] key, byte[] data) {
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        try {
            mac.init(keySpec);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        return mac.doFinal(data);
    }

    private static Keys deriveNtorKeys(byte[] keySeed) {
        byte[] prev = new byte[0];
        int totalSize = 92;
        ByteBuffer finalKey = ByteBuffer.allocate(totalSize);
        for (int keyNumber = 1; totalSize > 0; keyNumber++) {
            ByteBuffer temp = ByteBuffer.allocate(prev.length + NTOR_PROTOID.length + ":key_expand".length() + 1);
            temp.put(prev);
            temp.put(NTOR_PROTOID);
            temp.put(":key_expand".getBytes());
            temp.put((byte) keyNumber);
            prev = hmac(keySeed, temp.array());
            int bytesDone = Math.min(totalSize, prev.length);
            totalSize -= bytesDone;
            finalKey.put(prev, 0, bytesDone);
        }
        byte[][] keys = new byte[][]{{SHA1_LENGTH}, {SHA1_LENGTH}, {KEY_LENGTH}, {KEY_LENGTH}, {SHA1_LENGTH}};
        finalKey.position(0);
        for (int i = 0; i < keys.length; i++) {
            keys[i] = new byte[keys[i][0]];
            finalKey.get(keys[i]);
        }
        return new Keys(keys);
    }

    public static Keys finishNtorHandshake(AsymmetricCipherKeyPair keyPair, X25519PublicKeyParameters publicKey, RelayProperties properties, byte[] auth) {
        byte[] secret = Handshake.calculateSharedSecret((X25519PrivateKeyParameters) keyPair.getPrivate(), publicKey);
        X25519PublicKeyParameters ntorOnionKey = new X25519PublicKeyParameters(properties.ntorOnionKey());
        byte[] ntorSecret = Handshake.calculateSharedSecret((X25519PrivateKeyParameters) keyPair.getPrivate(), ntorOnionKey);
        ByteBuffer secretInput = ByteBuffer.allocate(180 + NTOR_PROTOID.length);
        secretInput.put(secret);
        secretInput.put(ntorSecret);
        secretInput.put(properties.fingerprint());
        secretInput.put(properties.ntorOnionKey());
        secretInput.put(((X25519PublicKeyParameters) keyPair.getPublic()).getEncoded());
        secretInput.put(publicKey.getEncoded());
        secretInput.put(NTOR_PROTOID);
        byte[] verify = hmac((new String(NTOR_PROTOID) + ":verify").getBytes(), secretInput.array());
        ByteBuffer authInput = ByteBuffer.allocate(116 + verify.length + NTOR_PROTOID.length + "Server".length());
        authInput.put(verify);
        authInput.put(properties.fingerprint());
        authInput.put(properties.ntorOnionKey());
        authInput.put(publicKey.getEncoded());
        authInput.put(((X25519PublicKeyParameters) keyPair.getPublic()).getEncoded());
        authInput.put(NTOR_PROTOID);
        authInput.put("Server".getBytes());
        byte[] authVerify = hmac((new String(NTOR_PROTOID) + ":mac").getBytes(), authInput.array());
        if (!Arrays.equals(authVerify, auth)) return null;
        byte[] keySeed = hmac((new String(NTOR_PROTOID) + ":key_extract").getBytes(), secretInput.array());
        return deriveNtorKeys(keySeed);
    }

}
