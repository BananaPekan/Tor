package banana.pekan.torclient.tor.cell.cells.relay.commands;

import banana.pekan.torclient.tor.Handshake;
import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;
import banana.pekan.torclient.tor.crypto.Cryptography;
import banana.pekan.torclient.tor.directory.RelayProperties;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.nio.ByteBuffer;

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
        byte[] linkSpecifiers = properties.createLinkSpecifiers();
        ByteBuffer buffer = ByteBuffer.allocate(1 + linkSpecifiers.length + ntorBlock.length);
        // NSPEC - number of link specifiers
        buffer.put(properties.getLinkSpecifierCount());
        // Link specifiers
        buffer.put(linkSpecifiers);
        // ntor block
        buffer.put(ntorBlock);
        return buffer.array();
    }
}
