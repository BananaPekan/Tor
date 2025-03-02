package banana.pekan.torclient.tor.cell.cells.relay.commands;

import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;

import java.nio.Buffer;
import java.nio.ByteBuffer;

public class BeginCommand extends RelayCell {

    String host;
    int port;

    public BeginCommand(int circuitId, int version, short streamId, String host, int port) {
        super(circuitId, version, false, BEGIN, streamId);
        this.host = host;
        this.port = port;
    }

    @Override
    protected byte[] getRelayBody() {
        ByteBuffer buffer = ByteBuffer.allocate(host.length() + String.valueOf(port).length() + 6);
        buffer.put(host.getBytes());
        buffer.put(":".getBytes());
        buffer.put(String.valueOf(port).getBytes());
        buffer.put((byte) 0);
        // flags
        buffer.put(new byte[4]);
        return buffer.array();
    }
}
