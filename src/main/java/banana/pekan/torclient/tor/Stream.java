package banana.pekan.torclient.tor;

import banana.pekan.torclient.tor.cell.Cell;
import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;
import banana.pekan.torclient.tor.cell.cells.relay.commands.DataCommand;
import banana.pekan.torclient.tor.cell.cells.relay.commands.EndCommand;

import java.util.concurrent.ConcurrentLinkedQueue;

public class Stream {

    String host;
    int port;
    short streamId;
    Circuit circuit;
    ConcurrentLinkedQueue<byte[]> receivedData;
    private boolean ended;
    private Cell last;

    public Stream(Circuit circuit, String host, int port) {
        this.host = host;
        this.port = port;
        System.out.println(circuit.cellQueue.peek());
        this.streamId = circuit.createNewStream(host, port);
        this.circuit = circuit;
        this.receivedData = new ConcurrentLinkedQueue<>();

        Thread listener = new Thread(() -> {
            while (!hasEnded() && circuit.isActive()) {
                if (last != circuit.cellQueue.peek()) {
                    last = circuit.cellQueue.peek();
//                    System.out.println("Last: " + last);
                    if (last instanceof DataCommand) {
//                        System.out.println(((DataCommand) last).getStreamId());
                    }
                }
                EndCommand endCommand = circuit.receiveCellImmediate(Cell.RELAY, streamId, RelayCell.END);
                if (endCommand != null) {
                    endStream(false);
                    break;
                }

                DataCommand dataCommand = circuit.receiveCellImmediate(Cell.RELAY, streamId, RelayCell.DATA);
                if (dataCommand != null) {
                    receivedData.add(dataCommand.getData());
                }
            }
        });
        listener.start();
    }

    public byte[] pollData() {
        if (receivedData.isEmpty()) return hasEnded() ? null : new byte[0];
        return receivedData.poll();
    }

    public void sendData(byte[] data) {
        circuit.sendCell(new DataCommand(circuit.getCircuitId(), circuit.getProtocolVersion(), streamId, data));
    }

    void endStream(boolean clientInitiated) {
        if (clientInitiated) {
            circuit.sendCell(new EndCommand(circuit.getCircuitId(), circuit.getProtocolVersion(), streamId, (byte) 1));
        }
        ended = true;
        System.out.println("The stream " + streamId + " has been ended: " + clientInitiated);
    }

    boolean hasEnded() {
        return ended;
    }

}
