package banana.pekan.torclient.tor.cell.cells.relay;

import banana.pekan.torclient.tor.cell.Cell;
import banana.pekan.torclient.tor.cell.cells.relay.commands.*;

import java.nio.ByteBuffer;
import java.util.Random;

public abstract class RelayCell extends Cell {

    public static class EncryptedRelayCell extends RelayCell {
        public EncryptedRelayCell(int circuitId, int version, boolean isEarly, byte[] encryptedBody) {
            super(circuitId, version, isEarly, (byte) 0, (short) 0);
            setEncryptedBody(encryptedBody);
        }
        public byte[] getEncryptedBody() {
            return encryptedBody;
        }

        @Override
        protected byte[] getRelayBody() {
            return new byte[0];
        }
    }

    public record Extension(byte type, byte[] data) {}

    protected static final byte BEGIN_DIR = 13;
    public static final byte CONNECTED = 4;
    public static final byte DATA = 2;
    public static final byte SEND_ME = 5;
    public static final byte END = 3;
    public static final byte EXTEND2 = 14;
    public static final byte EXTENDED2 = 15;
    public static final byte BEGIN = 1;
    public static final byte INTRODUCE1 = 34;
    public static final byte ESTABLISH_RENDEZVOUS = 33;
    public static final byte RENDEZVOUS_ESTABLISHED = 39;
    public static final byte INTRODUCE_ACK = 40;
    public static final byte ANY = -1;

    byte relayCommand;
    byte[] recognized;
    short streamId;
    byte[] encryptedBody;

    public RelayCell(int circuitId, int version, boolean isEarly, byte relayCommand, short streamId) {
        super(circuitId, isEarly ? RELAY_EARLY : RELAY, version);
        recognized = new byte[2];
        this.relayCommand = relayCommand;
        this.streamId = streamId;
    }

    protected abstract byte[] getRelayBody();

    public byte getRelayCommand() {
        return relayCommand;
    }

    public short getStreamId() {
        return streamId;
    }

    public byte[] serialiseUnencryptedRelayBody() {
        byte[] relayBody = getRelayBody();
        ByteBuffer payload = ByteBuffer.allocate(509);
        payload.put(relayCommand);
        payload.put(recognized);
        payload.putShort(streamId);
        payload.put(new byte[4]); // digest
        payload.putShort((short) relayBody.length);
        payload.put(relayBody);
        // padding
        payload.put(new byte[4]);
        byte[] padding = new byte[payload.remaining()];
        new Random().nextBytes(padding);
        payload.put(payload.position(), padding);

        return payload.array();
    }

    public void setEncryptedBody(byte[] encryptedBody) {
        this.encryptedBody = encryptedBody;
    }

    @Override
    protected byte[] serialiseBody() {
        return encryptedBody;
    }

    public static RelayCell interpretRelayCell(int circuitId, int version, byte[] relayPayload, boolean ignoreBody) {
        ByteBuffer buffer = ByteBuffer.wrap(relayPayload);
        byte command = buffer.get();
        byte[] recognized = new byte[2];
        buffer.get(recognized);
        short streamId = buffer.getShort();
        buffer.get(new byte[4]);
        short bodyLength = buffer.getShort();
        byte[] body = new byte[bodyLength];
        buffer.get(body);
        switch (command) {
            case CONNECTED:
//                if (ignoreBody)
                return new ConnectedCommand(circuitId, version, streamId);
            case DATA:
                return new DataCommand(circuitId, version, streamId, body);
            case END:
                return new EndCommand(circuitId, version, streamId, body[0]);
            case EXTENDED2:
                short hlen = (short) ((body[0] << 8) | body[1]); // constant (64);
                byte[] publicKey = new byte[32];
                byte[] auth = new byte[32];
                System.arraycopy(body, 2, publicKey, 0, publicKey.length);
                System.arraycopy(body, 34, auth, 0, auth.length);
                return new Extended2Command(circuitId, version, streamId, publicKey, auth);
            case SEND_ME:
                if (streamId == 0) {
                    ByteBuffer sendMe = ByteBuffer.wrap(body);
                    int sendMeVersion = sendMe.get();
                    if (sendMeVersion == 1) {
                        int dataLength = sendMe.getShort();
                        byte[] data = new byte[dataLength];
                        sendMe.get(data);
                        return new SendMeCommand(circuitId, version, streamId, data);
                    }
                }
                return new SendMeCommand(circuitId, version, streamId);
            case RENDEZVOUS_ESTABLISHED:
                return new RendezvousEstablished(circuitId, version);
            case INTRODUCE_ACK:
                ByteBuffer dataBuffer = ByteBuffer.wrap(body);
                short status = dataBuffer.getShort();
                Extension[] extensions = new Extension[dataBuffer.get()];

                for (int i = 0; i < extensions.length; i++) {
                    byte type = dataBuffer.get();
                    byte length = dataBuffer.get();
                    byte[] data = new byte[length];
                    dataBuffer.get(data);
                    extensions[i] = new Extension(type, data);
                }

                return new IntroduceAckCommand(circuitId, version, status, extensions);
            default:
                throw new Error("Encountered an unknown relay command: " + command);
        }
    }

}
