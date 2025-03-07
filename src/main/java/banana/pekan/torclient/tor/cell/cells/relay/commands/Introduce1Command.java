package banana.pekan.torclient.tor.cell.cells.relay.commands;

import banana.pekan.torclient.tor.Handshake;
import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;
import banana.pekan.torclient.tor.crypto.Cryptography;
import banana.pekan.torclient.tor.directory.RelayProperties;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

public class Introduce1Command extends RelayCell {

    RelayProperties introductionRelay;
    byte[] rendezvousCookie;
    RelayProperties rendezvousPoint;
    AsymmetricCipherKeyPair temporaryKeyPair;

    public Introduce1Command(int circuitId, int version, RelayProperties introductionRelay, byte[] rendezvousCookie, RelayProperties rendezvousPoint) {
        super(circuitId, version, false, INTRODUCE1, (short) 0);
        this.introductionRelay = introductionRelay;
        this.rendezvousCookie = rendezvousCookie;
        this.rendezvousPoint = rendezvousPoint;
        this.temporaryKeyPair = Cryptography.generateX25519KeyPair();
    }

    private byte[] getPlaintext(int headerSize) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        //      RENDEZVOUS_COOKIE                          [20 bytes]
        stream.writeBytes(rendezvousCookie);
        //      N_EXTENSIONS                               [1 byte]
        //      N_EXTENSIONS times:
        //          EXT_FIELD_TYPE                         [1 byte]
        //          EXT_FIELD_LEN                          [1 byte]
        //          EXT_FIELD                              [EXT_FIELD_LEN bytes]
        stream.write(0);
        //      ONION_KEY_TYPE                             [1 bytes]
        stream.write(1);
        //      ONION_KEY_LEN                              [2 bytes]
        stream.write(0);
        stream.write(32);
        //      ONION_KEY                                  [ONION_KEY_LEN bytes]
        stream.writeBytes(rendezvousPoint.ntorOnionKey());
        //      NSPEC      (Number of link specifiers)     [1 byte]
        stream.write(rendezvousPoint.getLinkSpecifierCount());
        //      NSPEC times:
        //          LSTYPE (Link specifier type)           [1 byte]
        //          LSLEN  (Link specifier length)         [1 byte]
        //          LSPEC  (Link specifier)                [LSLEN bytes]
        stream.writeBytes(rendezvousPoint.createLinkSpecifiers());
        //      PAD        (optional padding)              [up to end of plaintext]
        int sizeTakenUp = headerSize + 64; // headerSize + overhead -> we need to add some overhead because the encryption can enlarge the final size.
        int relayDataMax = 490;
        int paddingSize = relayDataMax - sizeTakenUp;
        int padding = paddingSize - stream.size();
        stream.writeBytes(new byte[padding]);

        return stream.toByteArray();
    }

    static String PROTOID = "tor-hs-ntor-curve25519-sha3-256-1";
    //      t_hsenc    = PROTOID | ":hs_key_extract"
    static String PROTOID_EXTRACT = PROTOID + ":hs_key_extract";
    //      m_hsexpand = PROTOID | ":hs_key_expand"
    static String PROTOID_EXPAND = PROTOID + ":hs_key_expand";

    private byte[][] kdf(byte[] B, byte[] authKey, byte[] subcredential) {
        //             intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID
        ByteArrayOutputStream introSecretHsInput = new ByteArrayOutputStream();
        introSecretHsInput.writeBytes(Handshake.calculateSharedSecret((X25519PrivateKeyParameters) temporaryKeyPair.getPrivate(), new X25519PublicKeyParameters(B)));
        introSecretHsInput.writeBytes(authKey);
        introSecretHsInput.writeBytes(((X25519PublicKeyParameters) temporaryKeyPair.getPublic()).getEncoded());
        introSecretHsInput.writeBytes(B);
        introSecretHsInput.writeBytes(PROTOID.getBytes());
        //             hs_keys = SHAKE256_KDF(intro_secret_hs_input | t_hsenc | info, S_KEY_LEN+MAC_LEN)
        introSecretHsInput.writeBytes(PROTOID_EXTRACT.getBytes());
        //             info = m_hsexpand | N_hs_subcred
        introSecretHsInput.writeBytes(PROTOID_EXPAND.getBytes());
        introSecretHsInput.writeBytes(subcredential);

        byte[] hsKeys = new byte[Cryptography.CIPHER_KEY_LENGTH + Cryptography.MAC_KEY_LENGTH];
        SHAKEDigest shakeDigest = new SHAKEDigest(256);
        shakeDigest.update(introSecretHsInput.toByteArray(), 0, introSecretHsInput.size());
        shakeDigest.doOutput(hsKeys, 0, hsKeys.length);
        //             ENC_KEY = hs_keys[0:S_KEY_LEN]
        byte[] encKey = new byte[Cryptography.CIPHER_KEY_LENGTH];
        System.arraycopy(hsKeys, 0, encKey, 0, encKey.length);
        //             MAC_KEY = hs_keys[S_KEY_LEN:S_KEY_LEN+MAC_KEY_LEN]
        byte[] macKey = new byte[Cryptography.CIPHER_KEY_LENGTH];
        System.arraycopy(hsKeys, encKey.length, macKey, 0, macKey.length);

        return new byte[][]{ encKey, macKey };
    }

    private byte[][] createEncrypted(byte[] B, byte[] authKey, byte[] subcredential, int headerSize) {
        byte[][] hsKeys = kdf(B, authKey, subcredential);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        //   and sends, as the ENCRYPTED part of the INTRODUCE1 message:
        //
        //          CLIENT_PK                [PK_PUBKEY_LEN bytes]
        stream.writeBytes(((X25519PublicKeyParameters) temporaryKeyPair.getPublic()).getEncoded());
        //          ENCRYPTED_DATA           [Padded to length of plaintext]
        Cipher encKey = Cryptography.createAesKey(Cipher.ENCRYPT_MODE, hsKeys[0]);
        stream.writeBytes(encKey.update(getPlaintext(headerSize)));

        return new byte[][]{ stream.toByteArray(), hsKeys[1]};
    }

    @Override
    protected byte[] getRelayBody() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        //     LEGACY_KEY_ID   [20 bytes]
        stream.writeBytes(new byte[20]);
        //     AUTH_KEY_TYPE   [1 byte]
        stream.write(2);
        //     AUTH_KEY_LEN    [2 bytes]
        byte[] authKey = (byte[]) introductionRelay.extra()[0];
        stream.write(authKey.length >> 8);
        stream.write(authKey.length & 0xFF);
        //     AUTH_KEY        [AUTH_KEY_LEN bytes]
        stream.writeBytes(authKey);
        //     N_EXTENSIONS    [1 byte]
        //     N_EXTENSIONS times:
        //       EXT_FIELD_TYPE [1 byte]
        //       EXT_FIELD_LEN  [1 byte]
        //       EXT_FIELD      [EXT_FIELD_LEN bytes]
        stream.write(0);
        //     ENCRYPTED        [Up to end of relay message body]
        byte[][] encrypted = createEncrypted((byte[]) introductionRelay.extra()[1], authKey, (byte[]) introductionRelay.extra()[2], stream.size());
        stream.writeBytes(encrypted[0]);
        //          MAC                      [MAC_LEN bytes]
        byte[] macKey = encrypted[1];
        byte[] output = stream.toByteArray();
        byte[] mac = Handshake.hsMac(macKey, output);

        ByteBuffer buffer = ByteBuffer.allocate(output.length + mac.length);
        buffer.put(output);
        buffer.put(mac);

        return buffer.array();
    }
}
