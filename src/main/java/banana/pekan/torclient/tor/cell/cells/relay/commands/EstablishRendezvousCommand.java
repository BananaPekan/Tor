package banana.pekan.torclient.tor.cell.cells.relay.commands;

import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class EstablishRendezvousCommand extends RelayCell {

    byte[] rendezvousCookie;

    public EstablishRendezvousCommand(int circuitId, int version) {
        super(circuitId, version, false, ESTABLISH_RENDEZVOUS, (short) 0);
        rendezvousCookie = new byte[20];
        try {
            SecureRandom.getInstanceStrong().nextBytes(rendezvousCookie);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] getRendezvousCookie() {
        return rendezvousCookie;
    }

    @Override
    protected byte[] getRelayBody() {
        return rendezvousCookie;
    }
}
