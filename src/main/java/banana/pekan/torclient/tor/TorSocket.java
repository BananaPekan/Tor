package banana.pekan.torclient.tor;

import banana.pekan.torclient.tor.directory.Directory;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

public class TorSocket {

    Stream stream;
    public static ConcurrentHashMap<String, Circuit> circuits = new ConcurrentHashMap<>();
    public static Guard guard = null;

    public TorSocket(Directory directory, String host, int port) {
        String[] urls = host.split("\\.");
        String mainHost = urls[urls.length - 2] + "." + urls[urls.length - 1];
        Circuit circuit = circuits.get(mainHost);
        if (guard == null) {
            guard = new Guard(directory.pickRandomGuard());
            System.out.println("Picked a guard: " + guard.host + ":" + guard.port);
            try {
                guard.connect();
                System.out.println("Connected to the guard.");
                System.out.println("Performing the initial tor handshake..");
                guard.initialHandshake();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        if (circuit == null || !circuit.isActive()) {
            System.out.println("Creating a circuit..");
            while (circuit == null) {
                circuit = guard.create2();
            }
            System.out.println("A circuit has been created: " + circuit.getCircuitId());
            System.out.println("Extending to a relay..");
            circuit.extend(directory.pickRandomRelay());
            System.out.println("Extended successfully.");
            System.out.println("Extending to an exit..");
            circuit.extend(directory.pickRandomExit());
            System.out.println("The circuit is complete.");
            circuits.put(mainHost, circuit);
        }

        System.out.println("Opening a new stream to: " + host + ":" + port);
        stream = new Stream(circuit, host, port);
        System.out.println("The stream has been successfully opened.");
    }

    public byte[] receive() {
        return stream.pollData();
//        if (data != null && data.length != 0) System.out.println("Received data: " + data.length);
//        return data;
    }

    public void close() {
        stream.endStream(true);
    }

    public void send(byte[] data) {
        stream.sendData(data);
    }

}
