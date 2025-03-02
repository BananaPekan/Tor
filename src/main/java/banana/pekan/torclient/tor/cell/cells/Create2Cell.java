package banana.pekan.torclient.tor.cell.cells;

import banana.pekan.torclient.tor.Handshake;
import banana.pekan.torclient.tor.cell.Cell;
import banana.pekan.torclient.tor.crypto.Cryptography;
import banana.pekan.torclient.tor.directory.RelayProperties;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Random;

public class Create2Cell extends Cell {

    AsymmetricCipherKeyPair temporaryKeypair;
    RelayProperties properties;

    public Create2Cell(int circuitId, int version, RelayProperties properties) {
        super(circuitId, CREATE2, version);
        this.temporaryKeypair = Cryptography.generateX25519KeyPair();
        this.properties = properties;
    }

    public AsymmetricCipherKeyPair getKeypair() {
        return temporaryKeypair;
    }

    @Override
    protected byte[] serialiseBody() {
        return Handshake.createNtorBlock(this.properties, (X25519PublicKeyParameters) temporaryKeypair.getPublic());
    }
}
