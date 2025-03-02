package banana.pekan.torclient.tor.cell;

import banana.pekan.torclient.tor.Relay;
import banana.pekan.torclient.tor.cell.cells.*;
import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;

public abstract class Cell {
    // Signifies that a client only needs to be able to parse a cell
    public @interface ClientDoesNotImplement {}
    // Signifies that a client completely ignores a cell
    public @interface ClientDoesNotCare {}

    public static int SHA1_LENGTH = 20;
    public static int FIXED_LENGTH_CELL = 514;
    public static final int VERSIONS = 7;
    public static final int CERTS = 129;
    public static final int AUTH_CHALLENGE = 130;
    public static final int NETINFO = 8;
    public static final int CREATE_FAST = 5;
    public static final int CREATED_FAST = 6;
    public static final int RELAY = 3;
    public static final int RELAY_EARLY = 9;
    public static final int CREATE2 = 10;
    public static final int CREATED2 = 11;
    public static final int PADDING = 0;
    public static final int DESTROY = 4;

    protected int circuitId;
    protected int command;
    protected int version;
    protected boolean variableLength;

    public Cell(int circuitId, int command, int version) {
        this.circuitId = circuitId;
        this.command = command;
        this.variableLength = isVariableLengthCell(command);
        this.version = version;
    }

    public int getCircuitId() {
        return circuitId;
    }

    public int getCommand() {
        return command;
    }

    protected abstract byte[] serialiseBody();

    public byte[] serialiseCell() {
        // The size of the cell is: circuitIdLength + 1 (command) + body.length + (padding, if the cell is a fixed length cell)
        byte[] body = serialiseBody();
        int circuitIdLength = version < 4 ? 2 : 4;
        int cellSize = circuitIdLength + 1 + (variableLength ? 2 : 0) + body.length;
        ByteBuffer cell = ByteBuffer.allocate(cellSize + (variableLength ? 0 : (FIXED_LENGTH_CELL - cellSize)));
        cell.order(ByteOrder.BIG_ENDIAN);

        // Circuit ID
        if (version >= 4) cell.putInt(circuitId);
        else {
            cell.put((byte) ((circuitId >> 8) & 0xFF));
            cell.put((byte) (circuitId & 0xFF));
        }

        // Command
        cell.put((byte) command);

        // Cell body length
        if (variableLength) {
            cell.put((byte) ((body.length >> 8) & 0xFF));
            cell.put((byte) (body.length & 0xFF));
        }

        // Cell body
        cell.put(body);

        // If the cell is a fixed length cell, then it needs to be padded to 514.
        // (*Technically if the version is below 4, then it needs to be 512, but these versions are not supported at the moment except for a few cell types.)
        if (!variableLength) {
            cell.put(cell.position(), new byte[cell.remaining()]);
        }

        return cell.array();
    }

    private static boolean isVariableLengthCell(int command) {
        return command == 7 || command >= 128;
    }

    public static Cell receiveCell(int circuitId, int protocolVersion, int command, InputStream inputStream) throws IOException {
        int length = 509;
        if (isVariableLengthCell(command)) {
            length = ByteBuffer.wrap(inputStream.readNBytes(2)).getShort();
        }

        byte[] cellData = inputStream.readNBytes(length);

        switch (command) {
            case VERSIONS:
                int[] versions = new int[length / 2];
                for (int i = 0; i < versions.length; i++) {
                    versions[i] = (cellData[i * 2] << 8) | cellData[i * 2 + 1];
                }
                return new VersionsCell(versions);
            case CERTS:
            {
                ByteBuffer buffer = ByteBuffer.wrap(cellData);
                int numOfCerts = buffer.get();
                CertsCell.Certificate[] certificates = new CertsCell.Certificate[numOfCerts];
                for (int i = 0; i < numOfCerts; i++) {
                    int certType = buffer.get();
                    int certLength = buffer.getShort();
                    byte[] certificate = new byte[certLength];
                    buffer.get(certificate, 0, certLength);
                    certificates[i] = new CertsCell.Certificate(certType, certLength, certificate);
                }
                return new CertsCell(protocolVersion, certificates);
            }
            case AUTH_CHALLENGE:
                // Since clients don't need to do anything with the data that is received via an auth challenge cell,
                // we can just read the data and not store it anywhere.
                return new AuthChallengeCell(protocolVersion);
            case NETINFO:
            {
                ByteBuffer buffer = ByteBuffer.wrap(cellData);
                int timestamp = buffer.getInt();

                int myAddressType = buffer.get();
                int myAddressLength = buffer.get();
                byte[] myAddressBytes = new byte[myAddressLength];
                buffer.get(myAddressBytes);
                InetAddress myAddress = InetAddress.getByAddress(myAddressBytes);

                int numOfRelayAddresses = buffer.get();
                InetAddress[] relayAddresses = new InetAddress[numOfRelayAddresses];
                for (int i = 0; i < numOfRelayAddresses; i++) {
                    int addressType = buffer.get();
                    int addressLength = buffer.get();
                    byte[] addressBytes = new byte[addressLength];
                    buffer.get(addressBytes);
                    relayAddresses[i] = InetAddress.getByAddress(addressBytes);
                }
                return new NetInfoCell(protocolVersion, timestamp, myAddress, relayAddresses);
            }
            case CREATED_FAST:
                byte[] keyMaterial = Arrays.copyOf(cellData, SHA1_LENGTH);
                byte[] derivativeKeyData = Arrays.copyOfRange(cellData, SHA1_LENGTH, 2 * SHA1_LENGTH);
                return new CreatedFastCell(circuitId, protocolVersion, keyMaterial, derivativeKeyData);
            case RELAY:
                return new RelayCell.EncryptedRelayCell(circuitId, protocolVersion, false, cellData);
            case CREATED2:
                ByteBuffer buffer = ByteBuffer.wrap(cellData);
                short hlen = buffer.getShort(); // constant (64)
                byte[] publicKey = new byte[32];
                buffer.get(publicKey);
                byte[] auth = new byte[32];
                buffer.get(auth);
                return new Created2Cell(circuitId, protocolVersion, publicKey, auth);
            case PADDING:
                return new PaddingCell(circuitId, protocolVersion);
            case DESTROY:
                System.out.println("DESTROYED BECAUSE: " + cellData[0]);
                return new DestroyCell(circuitId, protocolVersion, cellData[0]);
        }
        throw new Error("Encountered an unknown command: " + command);
    }

}
