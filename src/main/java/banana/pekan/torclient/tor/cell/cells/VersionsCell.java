package banana.pekan.torclient.tor.cell.cells;

import banana.pekan.torclient.tor.cell.Cell;

import java.util.Arrays;

public class VersionsCell extends Cell {

    int[] versions;

    public VersionsCell(int... versions) {
        super(0, VERSIONS, 0);
        this.versions = versions;
    }

    @Override
    public byte[] serialiseBody() {
        byte[] body = new byte[versions.length * 2];
        for (int i = 0; i < versions.length; i++) {
            body[i * 2] = (byte) ((versions[i] >> 8) & 0xFF);
            body[i * 2 + 1] = (byte) (versions[i] & 0xFF);
        }
        return body;
    }

    public int getHighestInCommon(VersionsCell otherVersions) {
        int highest = -1;
        for (int version : otherVersions.versions) {
            if (Arrays.stream(versions).anyMatch(value -> value == version))
                highest = Math.max(highest, version);
        }
        return highest;
    }

}
