package banana.pekan.torclient.tor.directory;

public record RelayProperties(String nickname, String host, int port, byte[] fingerprint, byte[] ntorOnionKey, byte[] ed25519Key, byte[] ipv6host, int ipv6port, Object[] extra) {

    RelayProperties(String nickname, String host, int port, byte[] fingerprint, byte[] ntorOnionKey) {
        this(nickname, host, port, fingerprint, ntorOnionKey, null, null, -1, null);
    }

}
