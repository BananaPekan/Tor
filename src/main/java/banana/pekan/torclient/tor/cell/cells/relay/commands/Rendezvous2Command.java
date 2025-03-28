package banana.pekan.torclient.tor.cell.cells.relay.commands;

import banana.pekan.torclient.tor.Circuit;
import banana.pekan.torclient.tor.Handshake;
import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;
import banana.pekan.torclient.tor.crypto.Keys;
import banana.pekan.torclient.tor.directory.RelayProperties;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

public class Rendezvous2Command extends RelayCell {

    X25519PublicKeyParameters publicKey;
    byte[] auth;

    public Rendezvous2Command(int circuitId, int version, byte[] publicKey, byte[] macAuth) {
        super(circuitId, version, false, RENDEZVOUS2, (short) 0);
        this.publicKey = new X25519PublicKeyParameters(publicKey);
        this.auth = macAuth;
    }

    public void finishHandshake(AsymmetricCipherKeyPair keyPair, byte[] hsNtorOnionKey, byte[] authKey, Circuit circuit) {
        Keys keys = Handshake.finishRendNtorHandshake(keyPair, publicKey, hsNtorOnionKey, authKey, auth);
        if (keys == null) throw new RuntimeException("Invalid mac.");
        circuit.addRelay(RelayProperties.nullProperties(), keys);
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] getRelayBody() {
        return new byte[0];
    }
}
