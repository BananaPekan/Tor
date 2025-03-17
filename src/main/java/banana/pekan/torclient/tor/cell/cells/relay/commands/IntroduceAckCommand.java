package banana.pekan.torclient.tor.cell.cells.relay.commands;

import banana.pekan.torclient.tor.cell.cells.relay.RelayCell;

public class IntroduceAckCommand extends RelayCell {

    short status;
    Extension[] extensions;

    public IntroduceAckCommand(int circuitId, int version, short status, Extension[] extensions) {
        super(circuitId, version, false, INTRODUCE_ACK, (short) 0);
        //     STATUS       [2 bytes]
        //     N_EXTENSIONS [1 bytes]
        //     N_EXTENSIONS times:
        //       EXT_FIELD_TYPE [1 byte]
        //       EXT_FIELD_LEN  [1 byte]
        //       EXT_FIELD      [EXT_FIELD_LEN bytes]
        //
        //   Recognized status values are:
        //
        //     [00 00] -- Success: message relayed to hidden service host.
        //     [00 01] -- Failure: service ID not recognized
        //     [00 02] -- Bad message format
        //     [00 03] -- Can't relay message to service
        this.status = status;
        this.extensions = extensions;
        System.out.println(extensions.length);
    }

    public short getStatus() {
        return status;
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] getRelayBody() {
        return new byte[0];
    }
}
