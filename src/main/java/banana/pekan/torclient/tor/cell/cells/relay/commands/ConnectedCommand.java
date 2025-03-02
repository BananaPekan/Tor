package banana.pekan.torclient.tor.cell.cells.relay.commands;

import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;

public class ConnectedCommand extends RelayCell {
    public ConnectedCommand(int circuitId, int version, short streamId) {
        super(circuitId, version, false, CONNECTED, streamId);
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] getRelayBody() {
        return new byte[0];
    }
}
