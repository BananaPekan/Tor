package banana.pekan.torclient.tor.directory;

import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public record RelayProperties(String nickname, String host, int port, byte[] fingerprint, byte[] ntorOnionKey, byte[] ed25519Key, byte[] ipv6host, int ipv6port, Object[] extra) {

    RelayProperties(String nickname, String host, int port, byte[] fingerprint, byte[] ntorOnionKey, byte[] ed25519Key, byte[] ipv6host, int ipv6port) {
        this(nickname, host, port, fingerprint, ntorOnionKey, ed25519Key, ipv6host, ipv6port, null);
    }

    public static RelayProperties nullProperties() {
        return new RelayProperties(null, "", -1, null, null, null, null, -1);
    }

    public byte[] createLinkSpecifiers() {
        int size = 8 + (ipv6host != null ? 20 : 0) + 22 + (ed25519Key != null ? 34 : 0);
        ByteBuffer buffer = ByteBuffer.allocate(size);
        buffer.put(createIpv4LinkSpecifier(host, port));
        if (ipv6host != null)
            buffer.put(createIpv6LinkSpecifier(ipv6host, ipv6port));
        buffer.put(createFingerprintLinkSpecifier(fingerprint));
        if (ed25519Key != null)
            buffer.put(createEd25519IdLinkSpecifier(ed25519Key));

        return buffer.array();
    }

    public byte getLinkSpecifierCount() {
        return (byte) (1 + (ipv6host != null ? 1 : 0) + 1 + (ed25519Key != null ? 1 : 0));
    }

    public static byte[] createLinkSpecifier(byte type, byte[] data) {
        byte[] linkSpecifier = new byte[2 + data.length];
        linkSpecifier[0] = type;
        linkSpecifier[1] = (byte) data.length;
        System.arraycopy(data, 0, linkSpecifier, 2, data.length);
        return linkSpecifier;
    }

    public static byte[] createIpv4LinkSpecifier(String host, int port) {
        // [00]	TLS-over-TCP, IPv4 address. A four-byte IPv4 address plus two-byte ORPort.
        ByteBuffer data = ByteBuffer.wrap(new byte[6]);
        Arrays.stream(host.split("\\.")).mapToInt(Integer::parseInt).forEach(i -> data.put((byte) i));
        data.putShort((short) port);
        return createLinkSpecifier((byte) 0, data.array());
    }

    public static byte[] createIpv6LinkSpecifier(String host, int port) {
        try {
            return createIpv6LinkSpecifier(Inet6Address.getByName(host).getAddress(), port);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] createIpv6LinkSpecifier(byte[] host, int port) {
        // [01]	TLS-over-TCP, IPv6 address. A sixteen-byte IPv6 address plus two-byte ORPort.
        ByteBuffer data = ByteBuffer.wrap(new byte[18]);
        data.put(host);
        data.putShort((short) port);
        return createLinkSpecifier((byte) 0, data.array());
    }

    public static byte[] createFingerprintLinkSpecifier(byte[] fingerprint) {
        // [02]	Legacy identity. A 20-byte SHA-1 identity fingerprint. At most one may be listed.
        return createLinkSpecifier((byte) 2, fingerprint);
    }

    public static byte[] createEd25519IdLinkSpecifier(byte[] ed25519Id) {
        // [03]	Ed25519 identity. A 32-byte Ed25519 identity. At most one may be listed.
        return createLinkSpecifier((byte) 3, ed25519Id);
    }

}
