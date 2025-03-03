package banana.pekan.torclient.tor.cell.cells.relay.commands;

import banana.pekan.torclient.tor.Handshake;
import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;
import banana.pekan.torclient.tor.crypto.Cryptography;
import banana.pekan.torclient.tor.directory.RelayProperties;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class Extend2Command extends RelayCell {

    RelayProperties properties;
    AsymmetricCipherKeyPair temporaryKeypair;

    public Extend2Command(int circuitId, int version, RelayProperties properties) {
        super(circuitId, version, true, EXTEND2, (short) 0);
        this.temporaryKeypair = Cryptography.generateX25519KeyPair();
        this.properties = properties;
    }

    public AsymmetricCipherKeyPair getKeypair() {
        return temporaryKeypair;
    }

    @Override
    protected byte[] getRelayBody() {
        byte[] ntorBlock = Handshake.createNtorBlock(properties, (X25519PublicKeyParameters) temporaryKeypair.getPublic());
        ByteBuffer buffer = ByteBuffer.allocate(31 + ntorBlock.length);
        // NSPEC - number of link specifiers
        buffer.put((byte) 2);
        // Link specifiers
        // specifier type - OR ipv4 & port
        buffer.put((byte) 0);
        // specifier length
        buffer.put((byte) 6);
        // host
        Arrays.stream(properties.host().split("\\.")).mapToInt(Integer::parseInt).forEach(i -> buffer.put((byte) i));
        // port
        buffer.putShort((short) properties.port());
        // specifier type - legacy RSA fingerprint
        buffer.put((byte) 2);
        // specifier length
        buffer.put((byte) 20);
        // fingerprint
        buffer.put(properties.fingerprint());
        // ntor block
        buffer.put(ntorBlock);
        return buffer.array();
    }
}
