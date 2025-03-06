package banana.pekan.torclient.tor.crypto;

import java.nio.ByteBuffer;
import java.util.Base64;

public record EdCertificate(int version, byte type, int expiration, byte certKeyType, byte[] certKey, Extension[] extensions, byte[] signature) {

    public record Extension(short length, byte type, byte flags, byte[] data) {}

    public int extensionsNum() {
        return extensions.length;
    }

    public static EdCertificate parseEd25519Cert(String cert) {
        ByteBuffer certificate = ByteBuffer.wrap(Base64.getDecoder().decode(cert.replace("-----BEGIN ED25519 CERT-----", "")
                .replace("-----END ED25519 CERT-----", "")
                .replaceAll("\\s+", "")));
        // VERSION	1	The version of this format
        // CERT_TYPE	1	Purpose and meaning of the cert
        // EXPIRATION_DATE	4	When the cert becomes invalid
        // CERT_KEY_TYPE	1	Type of CERTIFIED_KEY
        // CERTIFIED_KEY	32	Certified key, or its digest
        // N_EXTENSIONS	1	Number of extensions
        // N_EXTENSIONS times:
        // - ExtLen	2	Length of encoded extension body
        // - ExtType	1	Type of extension
        // - ExtFlags	1	Control interpretation of extension
        // - ExtData	ExtLen	Encoded extension body
        // SIGNATURE	64	Signature of all previous fields

        byte version = certificate.get();
        byte certType = certificate.get();
        int expirationDate = certificate.getInt();
        byte certKeyType = certificate.get();
        byte[] certifiedKey = new byte[32];
        certificate.get(certifiedKey, 0, 32);
        int extensionsNum = certificate.get();
        Extension[] extensions = new Extension[extensionsNum];

        for (int i = 0; i < extensionsNum; i++) {
            short extensionLength = certificate.getShort();
            byte extensionType = certificate.get();
            byte flags = certificate.get();
            byte[] extensionData = new byte[extensionLength];
            certificate.get(extensionData, 0, extensionLength);
            extensions[i] = new Extension(extensionLength, extensionType, flags, extensionData);
        }

        byte[] signature = new byte[64];
        certificate.get(signature, 0, 64);

        return new EdCertificate(version, certType, expirationDate, certKeyType, certifiedKey, extensions, signature);
    }

}
