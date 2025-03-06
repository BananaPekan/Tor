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
import java.nio.ByteBuffer;

import static banana.pekan.torclient.tor.Handshake.HS_NTOR_PROTOID;

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

    private byte[] getPlaintextData() {
        //      RENDEZVOUS_COOKIE                          [20 bytes]
        //      N_EXTENSIONS                               [1 byte]
        //      N_EXTENSIONS times:
        //          EXT_FIELD_TYPE                         [1 byte]
        //          EXT_FIELD_LEN                          [1 byte]
        //          EXT_FIELD                              [EXT_FIELD_LEN bytes]
        //      ONION_KEY_TYPE                             [1 bytes]
        //      ONION_KEY_LEN                              [2 bytes] (Technically 32)
        //      ONION_KEY                                  [ONION_KEY_LEN bytes]
        //      NSPEC      (Number of link specifiers)     [1 byte]
        //      NSPEC times:
        //          LSTYPE (Link specifier type)           [1 byte]
        //          LSLEN  (Link specifier length)         [1 byte]
        //          LSPEC  (Link specifier)                [LSLEN bytes]
        //      PAD        (optional padding)              [up to end of plaintext]

        byte[] linkSpecifiers = rendezvousPoint.createLinkSpecifiers();

        int size = rendezvousCookie.length + 37 + linkSpecifiers.length;
        ByteBuffer plaintext = ByteBuffer.allocate(size);
        plaintext.put(rendezvousCookie);
        plaintext.put((byte) 0);
        plaintext.put((byte) 0x01);
        plaintext.putShort((short) 32);
        plaintext.put(rendezvousPoint.ntorOnionKey());

        plaintext.put(rendezvousPoint.getLinkSpecifierCount());
        plaintext.put(linkSpecifiers);

        return plaintext.array();
    }

    private ByteBuffer createEncryptedField(byte[] hsNtorOnionKey, byte[] authKey, byte[] subcredential, ByteBuffer introData) {
        //   and sends, as the ENCRYPTED part of the INTRODUCE1 message:
        //
        //          CLIENT_PK                [PK_PUBKEY_LEN bytes]
        //          ENCRYPTED_DATA           [Padded to length of plaintext]
        //          MAC                      [MAC_LEN bytes]
        byte[] m_hsexpand = ByteBuffer.allocate(HS_NTOR_PROTOID.length + ":hs_key_expand".length()).put(HS_NTOR_PROTOID).put(":hs_key_expand".getBytes()).array();
        byte[] t_hsenc = ByteBuffer.allocate(HS_NTOR_PROTOID.length + ":hs_key_extract".length()).put(HS_NTOR_PROTOID).put(":hs_key_extract".getBytes()).array();
        //      t_hsverify = PROTOID | ":hs_verify"
        //      t_hsmac    = PROTOID | ":hs_mac"
        byte[] publicKey = ((X25519PublicKeyParameters) temporaryKeyPair.getPublic()).getEncoded();
        // intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID
        ByteBuffer introSecretHsInputBuffer = ByteBuffer.allocate(32 + authKey.length + publicKey.length + hsNtorOnionKey.length + HS_NTOR_PROTOID.length);
        introSecretHsInputBuffer.put(Handshake.calculateSharedSecret((X25519PrivateKeyParameters) temporaryKeyPair.getPrivate(), new X25519PublicKeyParameters(hsNtorOnionKey)));
        introSecretHsInputBuffer.put(authKey);
        introSecretHsInputBuffer.put(publicKey);
        introSecretHsInputBuffer.put(hsNtorOnionKey);
        introSecretHsInputBuffer.put(HS_NTOR_PROTOID);
        byte[] introSecretHsInput = introSecretHsInputBuffer.array();

        // info = m_hsexpand | N_hs_subcred
        byte[] info = ByteBuffer.allocate(subcredential.length + m_hsexpand.length).put(m_hsexpand).put(subcredential).array();
        // hs_keys = SHAKE256_KDF(intro_secret_hs_input | t_hsenc | info, S_KEY_LEN+MAC_LEN)
        SHAKEDigest shakeDigest = new SHAKEDigest(256);
        shakeDigest.update(introSecretHsInput, 0, introSecretHsInput.length);
        shakeDigest.update(t_hsenc, 0, t_hsenc.length);
        shakeDigest.update(info, 0, info.length);
        byte[] hsKeys = new byte[Cryptography.CIPHER_KEY_LENGTH + Cryptography.MAC_KEY_LENGTH];
        shakeDigest.doOutput(hsKeys, 0, hsKeys.length);

        // ENC_KEY = hs_keys[0:S_KEY_LEN]
        byte[] encryptionKey = new byte[Cryptography.CIPHER_KEY_LENGTH];
        System.arraycopy(hsKeys, 0, encryptionKey, 0, encryptionKey.length);
        // MAC_KEY = hs_keys[S_KEY_LEN:S_KEY_LEN+MAC_KEY_LEN]
        byte[] macKey = new byte[Cryptography.MAC_KEY_LENGTH];
        System.arraycopy(hsKeys, Cryptography.CIPHER_KEY_LENGTH, macKey, 0, macKey.length);

        byte[] plaintext = getPlaintextData();
        Cipher key = Cryptography.createAesKey(Cipher.ENCRYPT_MODE, encryptionKey);
        byte[] encrypted = key.update(plaintext);

        introData.put(publicKey);
        introData.put(encrypted);

        byte[] mac = Handshake.hsMac(macKey, introData.array());
        introData.put(mac);

        return introData;
    }

    @Override
    protected byte[] getRelayBody() {
        //     LEGACY_KEY_ID   [20 bytes] (all zeroes in the new format)
        //     AUTH_KEY_TYPE   [1 byte]
        //     AUTH_KEY_LEN    [2 bytes]
        //     AUTH_KEY        [AUTH_KEY_LEN bytes]
        //     N_EXTENSIONS    [1 byte]
        //     N_EXTENSIONS times:
        //       EXT_FIELD_TYPE [1 byte]
        //       EXT_FIELD_LEN  [1 byte]
        //       EXT_FIELD      [EXT_FIELD_LEN bytes]
        //     ENCRYPTED        [Up to end of relay message body]
        ByteBuffer buffer = ByteBuffer.allocate(490);
        buffer.put(new byte[20]);
        buffer.put((byte) 0x02);
        byte[] authKey = (byte[]) introductionRelay.extra()[0];
        buffer.putShort((short) authKey.length);
        buffer.put(authKey);
        buffer.put((byte) 0);

        byte[] hsNtorOnionKey = (byte[]) introductionRelay.extra()[1];
        byte[] subcredential = (byte[]) introductionRelay.extra()[2];

        return createEncryptedField(hsNtorOnionKey, authKey, subcredential, buffer).array();
    }
}
