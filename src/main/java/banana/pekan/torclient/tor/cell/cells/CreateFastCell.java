package banana.pekan.torclient.tor.cell.cells;

import banana.pekan.torclient.tor.cell.Cell;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CreateFastCell extends Cell {

    byte[] keyMaterial;

    public CreateFastCell(int circuitId, int version) {
        super(circuitId, CREATE_FAST, version);
        keyMaterial = new byte[SHA1_LENGTH];
        try {
            SecureRandom.getInstanceStrong().nextBytes(keyMaterial);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] getKeyMaterial() {
        return keyMaterial;
    }

    @Override
    protected byte[] serialiseBody() {

        return keyMaterial;
    }
}
