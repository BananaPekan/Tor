package banana.pekan.torclient.tor.directory;

import banana.pekan.torclient.tor.Circuit;
import banana.pekan.torclient.tor.Guard;
import banana.pekan.torclient.tor.cell.Cell;
import banana.pekan.torclient.tor.cell.cells.CreateFastCell;
import banana.pekan.torclient.tor.cell.cells.CreatedFastCell;
import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;
import banana.pekan.torclient.tor.cell.cells.relay.commands.BeginDirCommand;
import banana.pekan.torclient.tor.cell.cells.relay.commands.ConnectedCommand;
import banana.pekan.torclient.tor.cell.cells.relay.commands.DataCommand;
import banana.pekan.torclient.tor.cell.cells.relay.commands.EndCommand;
import banana.pekan.torclient.tor.crypto.Cryptography;
import banana.pekan.torclient.tor.crypto.Keys;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

public class Directory extends Guard {

    Circuit directoryCircuit;
    public ArrayList<byte[][]> hsDirs = new ArrayList<>();
    ArrayList<byte[][]> potentialGuards = new ArrayList<>();
    ArrayList<byte[][]> genericRelays = new ArrayList<>();
    ArrayList<byte[][]> potentialExits = new ArrayList<>();
    byte[] sharedRandValue = new byte[8];

    public Directory(String host, int port) {
        super(host, port);
    }

    private Circuit createFast() {
        CreateFastCell createFast = new CreateFastCell(Circuit.generateCircuitId(), protocolVersion);
        sendCell(createFast);
        CreatedFastCell createdFast = receiveCell(Cell.CREATED_FAST, createFast.getCircuitId());
        Keys keys = Cryptography.kdfTor(createFast.getKeyMaterial(), createdFast.getKeyMaterial());
        if (!Arrays.equals(keys.KH(), createdFast.getDerivedKeyData())) {
            close();
            return null;
        }
        this.keys.put(createdFast.getCircuitId(), keys);
        return new Circuit(createdFast.getCircuitId(), this);
    }

    public void directoryConnect() throws IOException {
        if (directoryCircuit != null) return;
        connect();
        initialHandshake();
        Circuit circuit = createFast();
        assert circuit != null;
        this.directoryCircuit = addCircuit(circuit);
        this.directoryCircuit.ignoreLastDigest();
    }

    private void parseRelay(String[] lines, int relayStart) {
        byte[] fingerprint = Base64.getDecoder().decode(lines[relayStart].split(" ")[2]);
        while (true) {
            if (lines[++relayStart].startsWith("m ")) break;
        }
        String microId = lines[relayStart++].split(" ")[1];
        List<String> status = List.of(lines[relayStart].toLowerCase().split(" "));
        if (!status.contains("valid") || !status.contains("running") || !status.contains("stable")) return;
        byte[][] info = new byte[2][];
        info[0] = fingerprint;
        info[1] = microId.getBytes();
        if (status.contains("guard")) potentialGuards.add(info);
        if (status.contains("hsdir")) hsDirs.add(info);
        if (status.contains("exit")) potentialExits.add(info);
        genericRelays.add(info);
    }

    public RelayProperties pickRandomGuard() {
        try {
            return fetchRelayDescriptor(potentialGuards.get(new Random().nextInt(potentialGuards.size())));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public RelayProperties pickRandomRelay() {
        try {
            return fetchRelayDescriptor(genericRelays.get(new Random().nextInt(genericRelays.size())));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public RelayProperties pickRandomExit() {
        try {
            return fetchRelayDescriptor(potentialExits.get(new Random().nextInt(potentialExits.size())));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    private void parseConsensus(String consensus) {
        String[] lines = consensus.split("\n");
        int start = 0;
        for (String line : lines) {
            if (line.startsWith("r ")) {
                parseRelay(lines, start);
            }
            start++;
        }
        // Could read until directory-footer, but currently not doing so.
    }

    public void readConsensus(String path) {
        try {
            parseConsensus(Files.readString(Path.of(path)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void test(String hs) throws IOException {
        directoryConnect();

        String httpRequest = "GET /tor/hs/3/" + hs + " HTTP/1.0\r\n\r\n";

        int circuitId = directoryCircuit.getCircuitId();
        short streamId = directoryCircuit.createNewDirStream();

        directoryCircuit.sendCell(new DataCommand(circuitId, protocolVersion, streamId, httpRequest.getBytes()));

        StringBuilder descriptorBuilder = new StringBuilder();

        while (true) {
            RelayCell relayCell = directoryCircuit.receiveCell(Cell.RELAY, streamId, RelayCell.ANY);
            if (relayCell instanceof EndCommand) break;
            byte[] bytes = ((DataCommand) relayCell).getData();
            String part = new String(bytes);
            descriptorBuilder.append(part);
        }

        System.out.println(descriptorBuilder);

    }

    public void fetchConsensus() throws IOException {
        directoryConnect();

        String httpRequest = "GET /tor/status-vote/current/consensus-microdesc/D586D1+14C131+E8A9C4+ED03BB+0232AF+49015F+EFCBE7+23D15D+27102B.z HTTP/1.0\r\n\r\n";

        int circuitId = directoryCircuit.getCircuitId();
        short streamId = (short) new Random().nextInt();
        directoryCircuit.sendCell(new BeginDirCommand(circuitId, protocolVersion, streamId));
        ConnectedCommand connectedCommand = directoryCircuit.receiveCell(RelayCell.RELAY, streamId, RelayCell.CONNECTED);
        System.out.println(connectedCommand);

        directoryCircuit.sendCell(new DataCommand(circuitId, protocolVersion, streamId, httpRequest.getBytes()));

        boolean write = false;
        Inflater inflater = new Inflater();
        byte[] outputBuffer = new byte[1024];

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        while (true) {
            DataCommand data = directoryCircuit.receiveCell(Cell.RELAY, streamId, RelayCell.DATA);
            byte[] bytes = data.getData();
            if (!write) {
                String str = new String(data.getData());
                if (str.contains("HTTP/")) {
                    int statusCode = Integer.parseInt(str.split(" ")[1]);
                    if (statusCode == 404) break;
                }
                if (!str.contains("Vary: X-Or-Diff-From-Consensus\r\n\r\n")) continue;
                write = true;
                int index = str.indexOf("Vary: X-Or-Diff-From-Consensus\r\n\r\n");
                index += "Vary: X-Or-Diff-From-Consensus\r\n\r\n".length();
                byte[] d = data.getData();
                byte[] output = new byte[d.length - index];
                if (d.length - index >= 0) System.arraycopy(d, index, output, 0, d.length - index);
                bytes = output;
            }

            inflater.setInput(bytes);

            try {
                while (!inflater.needsInput()) {
                    int decompressedDataLength = inflater.inflate(outputBuffer);
                    if (decompressedDataLength == 0) break;
                    byteArrayOutputStream.write(outputBuffer, 0, decompressedDataLength);
                }
            } catch (DataFormatException e) {
                System.err.println("Data format exception: " + e.getMessage());
                break;
            }

            if (inflater.finished()) break;
        }

        inflater.end();

        directoryCircuit.receiveCell(Cell.RELAY, streamId, RelayCell.END);

        if (!write) {
            System.out.println("Failed.");
        }
        else {
            System.out.println("Consensus.");
            // Get current random value
            String consensus = byteArrayOutputStream.toString();
            String sharedRandValue = consensus.split("shared-rand-current-value ")[1].split("\n")[0];
            sharedRandValue = sharedRandValue.split(" ")[1].strip();
            this.sharedRandValue = Base64.getDecoder().decode(sharedRandValue);

            parseConsensus(consensus);
        }

    }

    int memcmp(byte[] b1, byte[] b2, int sz){
        for(int i = 0; i < sz; i++){
            if(b1[i] != b2[i]){
                if((b1[i] >= 0 && b2[i] >= 0)||(b1[i] < 0 && b2[i] < 0))
                    return b1[i] - b2[i];
                if(b1[i] < 0 && b2[i] >= 0)
                    return 1;
                if(b2[i] < 0 && b1[i] >=0)
                    return -1;
            }
        }
        return 0;
    }

    public static String[] splitString(String str, int chunkLength) {
        ArrayList<String> parts = new ArrayList<>();
        while (true) {
            if (str.length() < chunkLength) {
                if (!str.isEmpty()) parts.add(str);
                break;
            }
            parts.add(str.substring(0, chunkLength));
            str = str.substring(chunkLength);
        }
        return parts.toArray(new String[0]);
    }

    public String[] sendRequest(String httpRequest) {
        String[] request = splitString(httpRequest, 490);

        System.out.println("sending..");

        int circuitId = directoryCircuit.getCircuitId();
        short streamId = directoryCircuit.createNewDirStream();

        for (String req : request) {
            directoryCircuit.sendCell(new DataCommand(circuitId, protocolVersion, streamId, req.getBytes()));
        }

        StringBuilder descriptorBuilder = new StringBuilder();

        while (true) {
            RelayCell relayCell = directoryCircuit.receiveCell(Cell.RELAY, streamId, RelayCell.ANY);
            if (relayCell instanceof EndCommand) break;
            byte[] bytes = ((DataCommand) relayCell).getData();
            String part = new String(bytes);
            descriptorBuilder.append(part);
        }

        String descriptors;
        try {
            descriptors = descriptorBuilder.toString().split("\r\n\r\n")[1];
            ArrayList<String> descs = new ArrayList<>();
            for (String descriptor : descriptors.split("\n")) {
                if (descriptor.contains("id ed25519 ")) {
                    descs.add(descriptor.split("id ed25519 ")[1]);
                }
            }
            return descs.toArray(String[]::new);
        }
        catch (Exception e) {
            return null;
        }
    }

    private Directory createDirectory(String dir) {
        Directory directory = new Directory(dir.split(":")[0], Integer.parseInt(dir.split(":")[1]));
        try {
            directory.directoryConnect();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return directory;
    }

    private static byte[] getHsRelayIndex(byte[] ed_id, byte[] sharedRandValue) {
        try {
            MessageDigest h = MessageDigest.getInstance("SHA3-256");
            h.update("node-idx".getBytes());
            h.update(ed_id);
            h.update(sharedRandValue);
            h.update(getIntervalNum());
            byte[] value = new byte[8];
            value[value.length - 2] = 5;
            value[value.length - 1] = (byte) 160;
            h.update(value);
            return h.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] getIntervalNum() {
        long seconds = Instant.now().getEpochSecond();
        long minutes = seconds / 60;
        minutes -= 12 * 60;
        minutes /= 1440;
        byte[] value = new byte[8];
        value[value.length - 2] = (byte) ((minutes >> 8) & 0xFF);
        value[value.length - 1] = (byte) (minutes & 0xFF);
        return value;
    }

    public byte[] getHsServiceIndex(byte[] blindedKey, int replica) {
        try {
            MessageDigest h = MessageDigest.getInstance("SHA3-256");
            h.update("store-at-idx".getBytes());
            h.update(blindedKey);
            byte[] replicaNum = new byte[8];
            replicaNum[replicaNum.length - 1] = (byte) replica;
            h.update(replicaNum);

            h.update(getIntervalNum());
            byte[] value = new byte[8];
            value[value.length - 2] = 5;
            value[value.length - 1] = (byte) 160;
            h.update(value);
            return h.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public RelayProperties fetchRelayDescriptor(byte[][] relayInfo) throws IOException {
        byte[] fingerprint = relayInfo[0];

        String httpRequest = "GET /tor/server/fp/" + HexFormat.of().formatHex(fingerprint).toUpperCase() + " HTTP/1.0\r\n\r\n";
        int circuitId = directoryCircuit.getCircuitId();
        short streamId = directoryCircuit.createNewDirStream();

        directoryCircuit.sendCell(new DataCommand(circuitId, protocolVersion, streamId, httpRequest.getBytes()));

        StringBuilder descriptorBuilder = new StringBuilder();

        while (true) {
            RelayCell relayCell = directoryCircuit.receiveCell(Cell.RELAY, streamId, RelayCell.ANY);
            if (relayCell instanceof EndCommand) break;
            byte[] bytes = ((DataCommand) relayCell).getData();
            String part = new String(bytes);
            descriptorBuilder.append(part);
        }

        String descriptor = descriptorBuilder.toString().split("\r\n\r\n")[1];

        String[] info = descriptor.split("\n")[0].strip().substring("router ".length()).split(" ");

        byte[] ntorOnionKey = Base64.getDecoder().decode(descriptor.split("\nntor-onion-key ")[1].split("\n")[0].strip());

        return new RelayProperties(info[0], info[1], Integer.parseInt(info[2]), fingerprint, ntorOnionKey);
    }

}
