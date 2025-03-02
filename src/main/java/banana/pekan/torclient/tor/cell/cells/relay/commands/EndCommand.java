package banana.pekan.torclient.tor.cell.cells.relay.commands;

import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;

public class EndCommand extends RelayCell {

    byte reason;

    public EndCommand(int circuitId, int version, short streamId, byte reason) {
        super(circuitId, version, false, END, streamId);
        this.reason = reason;
    }

    public byte getReason() {
        return reason;
    }

    @Override
    protected byte[] getRelayBody() {
        return new byte[]{ reason };
    }
}
