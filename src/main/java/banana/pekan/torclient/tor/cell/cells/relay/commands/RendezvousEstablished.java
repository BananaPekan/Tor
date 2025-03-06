package banana.pekan.torclient.tor.cell.cells.relay.commands;

import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;

public class RendezvousEstablished extends RelayCell {

    public RendezvousEstablished(int circuitId, int version) {
        super(circuitId, version, false, RENDEZVOUS_ESTABLISHED, (short) 0);
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] getRelayBody() {
        return new byte[0];
    }
}
