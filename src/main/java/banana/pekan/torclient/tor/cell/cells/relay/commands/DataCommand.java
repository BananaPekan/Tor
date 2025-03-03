package banana.pekan.torclient.tor.cell.cells.relay.commands;

import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;

public class DataCommand extends RelayCell {

    byte[] data;

    public DataCommand(int circuitId, int version, short streamId, byte[] data) {
        super(circuitId, version, false, DATA, streamId);
        this.data = data;
    }

    public byte[] getData() {
        return data;
    }

    @Override
    protected byte[] getRelayBody() {
        return data;
    }
}
