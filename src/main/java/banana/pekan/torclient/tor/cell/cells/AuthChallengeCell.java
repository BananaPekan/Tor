package banana.pekan.torclient.tor.cell.cells;

import banana.pekan.torclient.tor.cell.Cell;

@Cell.ClientDoesNotCare
public class AuthChallengeCell extends Cell {
    public AuthChallengeCell(int version) {
        super(0, AUTH_CHALLENGE, version);
    }

    @Override
    protected byte[] serialiseBody() {
        return new byte[0];
    }
}
