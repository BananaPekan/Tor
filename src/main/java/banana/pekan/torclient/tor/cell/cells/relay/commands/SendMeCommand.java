package banana.pekan.torclient.tor.cell.cells.relay.commands;

import banana.pekan.torclient.tor.Relay;
import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class SendMeCommand extends RelayCell {

    int sendMeVersion = 0;
    byte[] digest;

    public SendMeCommand(int circuitId, int version, short streamId) {
        super(circuitId, version, false, SEND_ME, streamId);
    }

    public SendMeCommand(int circuitId, int version, short streamId, byte[] digest) {
        super(circuitId, version, false, SEND_ME, streamId);
        this.sendMeVersion = 1;
        this.digest = digest;
        System.out.println(Arrays.toString(digest));
    }

    @Override
    protected byte[] getRelayBody() {
        ByteBuffer buffer = ByteBuffer.allocate(sendMeVersion == 0 ? 0 : 23);
        if (sendMeVersion == 1) {
            buffer.put((byte) sendMeVersion);
            buffer.putShort((short) digest.length);
            buffer.put(digest);
        }
        return buffer.array();
    }
}
