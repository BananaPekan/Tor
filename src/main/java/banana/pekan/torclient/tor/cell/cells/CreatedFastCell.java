package banana.pekan.torclient.tor.cell.cells;

import banana.pekan.torclient.tor.cell.Cell;

public class CreatedFastCell extends Cell {

    byte[] keyMaterial;
    byte[] derivedKeyData;

    public CreatedFastCell(int circuitId, int version, byte[] keyMaterial, byte[] derivedKeyData) {
        super(circuitId, CREATED_FAST, version);
        this.keyMaterial = keyMaterial;
        this.derivedKeyData = derivedKeyData;
    }

    public byte[] getKeyMaterial() {
        return keyMaterial;
    }

    public byte[] getDerivedKeyData() {
        return derivedKeyData;
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] serialiseBody() {
        return new byte[0];
    }
}
