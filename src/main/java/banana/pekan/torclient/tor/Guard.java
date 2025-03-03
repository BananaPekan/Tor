package banana.pekan.torclient.tor;

import banana.pekan.torclient.tor.cell.Cell;
import banana.pekan.torclient.tor.cell.cells.*;
import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;
import banana.pekan.torclient.tor.crypto.Keys;
import banana.pekan.torclient.tor.directory.RelayProperties;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

public class Guard extends Relay {

    InputStream inputStream;
    OutputStream outputStream;
    SSLSocket socket;
    protected int protocolVersion = 0;
    ConcurrentHashMap<Integer, Circuit> circuits;
    ConcurrentLinkedQueue<Cell> cellQueue = new ConcurrentLinkedQueue<>();

    public Guard(RelayProperties relayProperties) {
        super(relayProperties);
        this.circuits = new ConcurrentHashMap<>();
    }

    protected Guard(String host, int port) {
        super(host, port);
        this.circuits = new ConcurrentHashMap<>();
    }

    public boolean isConnected() {
        return this.socket != null && this.socket.isConnected();
    }

    public int getProtocolVersion() {
        return protocolVersion;
    }

    public Circuit addCircuit(Circuit circuit) {
        circuits.put(circuit.getCircuitId(), circuit);
        return circuit;
    }

    public void sendCellData(byte[] cellData) {
        if (!isConnected()) throw new Error("Cannot send a cell before a connection is made.");
        try {
            outputStream.write(cellData);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void sendCell(Cell cell) {
        sendCellData(cell.serialiseCell());
    }

    private void queueCell(Cell cell) {
        cellQueue.add(cell);
    }

    // Establishes a connection to the onion router with ssl
    public void connect() throws IOException {
        // Create a TrustManager that does not validate the certificates in the tls session
        TrustManager[] trustManagers = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
                    @Override
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
        };

        try {
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(null, trustManagers, new java.security.SecureRandom());
            this.socket = (SSLSocket) sslContext.getSocketFactory().createSocket(host, port);
            this.inputStream = socket.getInputStream();
            this.outputStream = socket.getOutputStream();
            Thread thread = new Thread(() -> {
                while (socket.isConnected()) {
//                    if (circuits.isEmpty()) continue;
                    // originally used but now unnecessary: if (!isConnected()) throw new Error("Cannot receive a cell before a connection is made.");
                    Cell cell;
                    try {
                        ByteBuffer circuitIdBytes = ByteBuffer.wrap(inputStream.readNBytes(protocolVersion < 4 ? 2 : 4));
                        int circuitId = protocolVersion >= 4 ? circuitIdBytes.getInt() : circuitIdBytes.getShort();
                        int command = inputStream.read();
                        cell = Cell.receiveCell(circuitId, protocolVersion, command, inputStream);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    if (cell instanceof PaddingCell) continue;
                    Circuit circuit = circuits.get(cell.getCircuitId());

                    if (cell instanceof DestroyCell) {
                        if (circuit != null) {
//                            circuit.queueCell(cell);
                            circuit.close();
                        }
//                        else queueCell(cell);
                        break;
                    }

                    if (circuit == null || cell.getCircuitId() == 0) {
                        queueCell(cell);
                        while (protocolVersion == 0 && cell instanceof VersionsCell);
                        continue;
                    }
                    if (cell instanceof RelayCell) {
                        byte[] encryptedBody = ((RelayCell.EncryptedRelayCell) cell).getEncryptedBody();
                        cell = RelayCell.interpretRelayCell(circuit.getCircuitId(), protocolVersion, circuit.decryptRelayPayload(encryptedBody), false);
                    }
                    circuit.queueCell(cell);
                }
            });
            thread.start();

        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    public void close() {
        // TODO: Replace with an actual close function
        try {
            socket.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public <T extends Cell> T receiveCellTimeout(int cellType, int circuitId, int timeout) {
        Cell cell = cellQueue.peek();
        long current;
        long delta = 0;
        long last = System.nanoTime();
        while (cell == null || cell.getCommand() != cellType || cell.getCircuitId() != circuitId) {
            cell = cellQueue.peek();
            current = System.nanoTime();
            delta += current - last;
            last = current;
            if (delta / 1000000000L >= timeout) return null;
        }
        return (T) cellQueue.poll();
    }

    @SuppressWarnings("unchecked")
    public <T extends Cell> T receiveCell(int cellType, int circuitId) {
        Cell cell = cellQueue.peek();
        while (cell == null || cell.getCommand() != cellType || cell.getCircuitId() != circuitId)
            cell = cellQueue.peek();
        return (T) cellQueue.poll();
    }

    public <T extends Cell> T receiveCell(int cellType) {
        return receiveCell(cellType, 0);
    }

    public void initialHandshake() throws IOException {
        if (!isConnected()) throw new Error("No connection was made to the onion router.");
        VersionsCell supportedVersions = new VersionsCell(4, 5);
        sendCell(supportedVersions);
        VersionsCell relayVersions = receiveCell(Cell.VERSIONS);
        protocolVersion = supportedVersions.getHighestInCommon(relayVersions);
        if (protocolVersion == -1) {
            close();
            return;
        }
        // TODO: Validate the received certificates
        CertsCell certsCell = receiveCell(Cell.CERTS);

        AuthChallengeCell authChallengeCell = receiveCell(Cell.AUTH_CHALLENGE);

        NetInfoCell netInfoCell = receiveCell(Cell.NETINFO);

        // Finish the handshake by replying with a NetInfo cell
        sendCell(new NetInfoCell(protocolVersion, 0, socket.getInetAddress(), new InetAddress[0]));

        finishedInitialHandshake = true;
    }

    public Circuit create2() {
        Create2Cell create2Cell = new Create2Cell(Circuit.generateCircuitId(), protocolVersion, this.properties);
        sendCell(create2Cell);
        Created2Cell created2Cell = receiveCellTimeout(Cell.CREATED2, create2Cell.getCircuitId(), 5);
        if (created2Cell == null) {
            System.out.println("Circuit creation has timed out.");
            return null;
        }
        Keys keys = Handshake.finishNtorHandshake(create2Cell.getKeypair(), created2Cell.getPublicKey(), this.properties, created2Cell.getAuth());
        if (keys == null) {
            close();
            return null;
        }
        this.keys.put(created2Cell.getCircuitId(), keys);
        return addCircuit(new Circuit(created2Cell.getCircuitId(), this));
    }

}
