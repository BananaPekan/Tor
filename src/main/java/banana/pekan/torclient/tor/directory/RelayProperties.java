package banana.pekan.torclient.tor.directory;

public record RelayProperties(String nickname, String host, int port, byte[] fingerprint, byte[] ntorOnionKey) {
}
