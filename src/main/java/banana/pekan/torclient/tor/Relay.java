package banana.pekan.torclient.tor;

import banana.pekan.torclient.tor.crypto.Keys;
import banana.pekan.torclient.tor.directory.RelayProperties;

import java.util.HashMap;

public class Relay {

    protected String host;
    protected int port;
    boolean finishedInitialHandshake;
    protected HashMap<Integer, Keys> keys = new HashMap<>();
    protected RelayProperties properties;

    public Relay(RelayProperties relayProperties) {
        this(relayProperties.host(), relayProperties.port());
        this.properties = relayProperties;
    }

    public Relay(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public Keys getKeys(int circuitId) {
        return keys.get(circuitId);
    }

    public void setKeys(int circuitId, Keys keys) {
        this.keys.put(circuitId, keys);
    }

}
