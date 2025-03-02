package banana.pekan.torclient.tor.cell.cells;

import banana.pekan.torclient.tor.cell.Cell;

public class CertsCell extends Cell {

    public record Certificate(int type, int length, byte[] certificate) {
    }

    Certificate[] certificates;

    public CertsCell(int version, Certificate[] certificates) {
        super(0, CERTS, version);
        this.certificates = certificates;
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] serialiseBody() {
        return new byte[0];
    }
}
