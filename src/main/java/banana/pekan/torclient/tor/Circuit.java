package banana.pekan.torclient.tor;

import banana.pekan.torclient.tor.cell.Cell;
import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;
import banana.pekan.torclient.tor.cell.cells.relay.commands.*;
import banana.pekan.torclient.tor.crypto.Cryptography;
import banana.pekan.torclient.tor.crypto.Keys;
import banana.pekan.torclient.tor.directory.RelayProperties;

import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

public class Circuit {

    int circuitId;
    Guard guard;
    ArrayList<Relay> relays;
    ConcurrentLinkedQueue<Cell> cellQueue;
    ConcurrentHashMap<Short, int[]> streamWindows;
    int[] circuitWindow = new int[]{1000, 0, 1000, 0};
    byte[] lastDigest = new byte[0];
    boolean isActive;

    public Circuit(int circuitId, Guard guard, Relay... relays) {
        this.circuitId = circuitId;
        this.relays = new ArrayList<>(List.of(relays));
        this.relays.addFirst(guard);
        this.guard = guard;
        this.cellQueue = new ConcurrentLinkedQueue<>();
        this.streamWindows = new ConcurrentHashMap<>();
        this.isActive = true;
    }

    public void ignoreLastDigest() {
        lastDigest = null;
    }

    public static int generateCircuitId() {
        return new Random().nextInt() | 0x80000000;
    }

    public int getCircuitId() {
        return circuitId;
    }

    public void queueCell(Cell cell) {
        cellQueue.add(cell);
    }

    public int getProtocolVersion() {
        return guard.getProtocolVersion();
    }

    private void updateRelayDigest(byte[] relayPayload) {
        MessageDigest digest = relays.getLast().getKeys(circuitId).digestForward();
        byte[] digestBytes = Cryptography.updateDigest(digest, relayPayload);
//        if (lastDigest != null) lastDigest = digestBytes;
        lastDigest = null;
        System.arraycopy(digestBytes, 0, relayPayload, 5, 4);
    }

    private byte[] encryptRelayPayload(byte[] relayPayload) {
        for (int i = 0; i < relays.size(); i++) {
            Relay relay = relays.get(relays.size() - i - 1);
            Cipher encryptionKey = relay.getKeys(circuitId).encryptionKey();
            relayPayload = encryptionKey.update(relayPayload);
        }
        return relayPayload;
    }

    byte[] decryptRelayPayload(byte[] encryptedPayload) {
        for (Relay relay : relays) {
            Cipher decryptionKey = relay.getKeys(circuitId).decryptionKey();
            encryptedPayload = decryptionKey.update(encryptedPayload);
        }
        return encryptedPayload;
    }

    public void sendCell(Cell cell) {
        if (!isActive) return;
        int streamIdEnd = Integer.MAX_VALUE;
        if (cell instanceof RelayCell) {
            if (((RelayCell) cell).getRelayCommand() == RelayCell.END) {
                streamIdEnd = ((RelayCell) cell).getStreamId();
            }
            byte[] relayBody = ((RelayCell) cell).serialiseUnencryptedRelayBody();
            updateRelayDigest(relayBody);
            relayBody = encryptRelayPayload(relayBody);
            ((RelayCell) cell).setEncryptedBody(relayBody);
        }
        guard.sendCell(cell);
        if (streamIdEnd != Integer.MAX_VALUE)
            streamWindows.replace((short) streamIdEnd, new int[0]);
    }

    private void incrementWindow(int[] window, int increment, short streamId) {
        window[1]++;
        if (window[1] >= window[0] - increment) {
            if (lastDigest == null) sendCell(new SendMeCommand(circuitId, guard.getProtocolVersion(), streamId));
            else sendCell(new SendMeCommand(circuitId, guard.getProtocolVersion(), streamId, lastDigest));
            window[0] += increment;
        }
    }

    private void incrementCircuitWindow() {
        incrementWindow(circuitWindow, 100, (short) 0);
    }

    public <T extends Cell> T receiveCell(int cellType, int command) {
        return receiveCell(cellType, (short) 0, command);
    }

    public <T extends Cell> T receiveCellImmediate(int cellType, short streamId, int command) {
        if (!isActive) return null;
        Cell cell = cellQueue.peek();
        if (cell != null && cell.getCommand() == cellType) {
            if (cell instanceof RelayCell) {
                int relayCommand = ((RelayCell) cell).getRelayCommand();
                if (relayCommand == RelayCell.SEND_ME) {
                    System.out.println("send_me");
                    cellQueue.poll();
                    return null;
                }
                if (relayCommand != RelayCell.CONNECTED) {
                    if ((streamWindows.containsKey(streamId) && streamWindows.get(streamId).length == 0) ||
                            (streamWindows.containsKey(((RelayCell) cell).getStreamId()) && streamWindows.get(((RelayCell) cell).getStreamId()).length == 0)) {
                        cellQueue.poll();
                        return null;
                    }
                }
                if (((RelayCell) cell).getStreamId() != streamId) return null;
                if (command != RelayCell.ANY && relayCommand != command) return null;
                if (relayCommand == RelayCell.CONNECTED) {
                    streamWindows.put(streamId, new int[]{500, 0});
                }
                else if (relayCommand == RelayCell.DATA) {
                    incrementCircuitWindow();
                    incrementWindow(streamWindows.get(streamId), 50, streamId);
                }
                else if (relayCommand == RelayCell.END) {
                    streamWindows.replace(streamId, new int[0]);
                }
            }
            cellQueue.poll();
            return (T) cell;
        }
        return null;
    }

    public <T extends Cell> T receiveCell(int cellType, short streamId, int command) {
        if (!isActive) return  null;
        if (cellType == Cell.RELAY && command != RelayCell.CONNECTED && streamWindows.containsKey(streamId) && streamWindows.get(streamId).length == 0) {
            return null;
        }
        while (true) {
            T cell = receiveCellImmediate(cellType, streamId, command);
            if (cell != null) return cell;
        }
    }

    public short createNewDirStream() {
        short streamId = (short) new Random().nextInt(0, Short.MAX_VALUE);
        createNewDirStream(streamId);
        return streamId;
    }

    public void createNewDirStream(short streamId) {
        sendCell(new BeginDirCommand(circuitId, guard.getProtocolVersion(), streamId));
        ConnectedCommand connectedCommand = receiveCell(Cell.RELAY, streamId, RelayCell.CONNECTED);
    }

    public short createNewStream(String host, int port) {
        short streamId = (short) new Random().nextInt(0, Short.MAX_VALUE);
        createNewStream(streamId, host, port);
        return streamId;
    }

    public void createNewStream(short streamId, String host, int port) {
        sendCell(new BeginCommand(circuitId, guard.getProtocolVersion(), streamId, host, port));
        ConnectedCommand connectedCommand = receiveCell(Cell.RELAY, streamId, RelayCell.CONNECTED);
        System.out.println(connectedCommand);
    }

    public void addRelay(RelayProperties properties, Keys keys) {
        Relay relay = new Relay(properties);
        relay.addKeys(circuitId, keys);
        relays.add(relay);
    }

    public boolean extend(RelayProperties properties) {
        Extend2Command extend2Command = new Extend2Command(circuitId, guard.getProtocolVersion(), properties);
        sendCell(extend2Command);
        Extended2Command extended2Command = receiveCell(Cell.RELAY, RelayCell.EXTENDED2);
        Keys keys = Handshake.finishNtorHandshake(extend2Command.getKeypair(), extended2Command.getPublicKey(), properties, extended2Command.getAuth());
        if (keys == null) {
            guard.close();
            return false;
        }
        addRelay(properties, keys);
        return true;
    }

    public boolean isActive() {
        return isActive;
    }

    public void close() {
        isActive = false;
    }

}
