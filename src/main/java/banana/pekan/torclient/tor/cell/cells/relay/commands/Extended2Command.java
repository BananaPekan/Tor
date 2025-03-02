package banana.pekan.torclient.tor.cell.cells.relay.commands;

import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

public class Extended2Command extends RelayCell {

    X25519PublicKeyParameters publicKey;
    byte[] auth;

    public Extended2Command(int circuitId, int version, short streamId, byte[] publicKey, byte[] auth) {
        super(circuitId, version, false, EXTENDED2, streamId);
        this.publicKey = new X25519PublicKeyParameters(publicKey);
        this.auth = auth;
    }

    public X25519PublicKeyParameters getPublicKey() {
        return publicKey;
    }

    public byte[] getAuth() {
        return auth;
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] getRelayBody() {
        return new byte[0];
    }
}
