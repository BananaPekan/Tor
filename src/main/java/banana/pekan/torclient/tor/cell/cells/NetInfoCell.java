package banana.pekan.torclient.tor.cell.cells;

import banana.pekan.torclient.tor.cell.Cell;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;

public class NetInfoCell extends Cell {

    int timestamp;
    InetAddress receiverAddress;
    InetAddress[] senderAddresses;

    public NetInfoCell(int version, int timestamp, InetAddress receiverAddress, InetAddress[] senderAddresses) {
        super(0, NETINFO, version);
        this.timestamp = timestamp;
        this.receiverAddress = receiverAddress;
        this.senderAddresses = senderAddresses;
    }

    @Override
    protected byte[] serialiseBody() {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(ByteBuffer.allocate(4).putInt(timestamp).array());
            byte[] receiverBytes = receiverAddress.getAddress();
            int receiverType = receiverBytes.length == 16 ? 6 : 4;
            outputStream.write(receiverType);
            outputStream.write(receiverBytes.length);
            outputStream.write(receiverBytes);

            outputStream.write(senderAddresses.length);
            for (InetAddress senderAddress : senderAddresses) {
                byte[] address = senderAddress.getAddress();
                int type = address.length == 16 ? 6 : 4;
                outputStream.write(type);
                outputStream.write(address.length);
                outputStream.write(address);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return outputStream.toByteArray();
    }
}
