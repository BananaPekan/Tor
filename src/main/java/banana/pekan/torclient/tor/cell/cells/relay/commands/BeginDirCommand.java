package banana.pekan.torclient.tor.cell.cells.relay.commands;

import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;

public class BeginDirCommand extends RelayCell {
    public BeginDirCommand(int circuitId, int version, short streamId) {
        super(circuitId, version, false, BEGIN_DIR, streamId);
    }

    @Override
    protected byte[] getRelayBody() {
        return new byte[0];
    }
}
