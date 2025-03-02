package banana.pekan.torclient.tor.cell.cells;

import banana.pekan.torclient.tor.cell.Cell;

public class PaddingCell extends Cell {

    public PaddingCell(int circuitId, int version) {
        super(circuitId, PADDING, version);
    }

    @Override
    protected byte[] serialiseBody() {
        return new byte[0];
    }
}
