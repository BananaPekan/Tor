package banana.pekan.torclient.tor.cell.cells;

import banana.pekan.torclient.tor.cell.Cell;

public class DestroyCell extends Cell {

    byte reason;

    public DestroyCell(int circuitId, int version, byte reason) {
        super(circuitId, DESTROY, version);
        this.reason = reason;
    }

    @Override
    protected byte[] serialiseBody() {
        return new byte[]{ reason };
    }
}
