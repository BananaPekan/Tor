package banana.pekan.torclient.tor.cell.cells;

import banana.pekan.torclient.tor.cell.Cell;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

public class Created2Cell extends Cell {

    X25519PublicKeyParameters publicKey;
    byte[] auth;

    public Created2Cell(int circuitId, int version, byte[] publicKey, byte[] auth) {
        super(circuitId, CREATED2, version);
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
    protected byte[] serialiseBody() {
        return new byte[0];
    }
}
