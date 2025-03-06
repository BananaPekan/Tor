package banana.pekan.torclient.tor.cell.cells.relay.commands;

import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;
import banana.pekan.torclient.tor.directory.RelayProperties;

import java.nio.ByteBuffer;

public class Introduce1Command extends RelayCell {

    RelayProperties relayProperties;

    public Introduce1Command(int circuitId, int version, RelayProperties relayProperties) {
        super(circuitId, version, false, INTRODUCE1, (short) 0);
        this.relayProperties = relayProperties;
    }

    @Override
    protected byte[] getRelayBody() {
        //     LEGACY_KEY_ID   [20 bytes]
        //     AUTH_KEY_TYPE   [1 byte]
        //     AUTH_KEY_LEN    [2 bytes]
        //     AUTH_KEY        [AUTH_KEY_LEN bytes]
        //     N_EXTENSIONS    [1 byte]
        //     N_EXTENSIONS times:
        //       EXT_FIELD_TYPE [1 byte]
        //       EXT_FIELD_LEN  [1 byte]
        //       EXT_FIELD      [EXT_FIELD_LEN bytes]
        //     ENCRYPTED        [Up to end of relay message body]
        ByteBuffer buffer = ByteBuffer.allocate(128);
        buffer.put(relayProperties.fingerprint());
        buffer.put((byte) 0x02);
        byte[] authKey = (byte[]) relayProperties.extra()[0];
        buffer.put(authKey);
        // NOT FINISHED
        return new byte[]{  };
    }
}
