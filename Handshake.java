import java.io.*;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;

public class Handshake 
{
    public static HandshakeSession performServerHandshake(ObjectInputStream in, ObjectOutputStream out) throws Exception 
    {
        byte[] clientNonce = (byte[]) in.readObject();
        System.out.println("[Handshake] Received client nonce.");

        PrivateKey serverPrivateKey = KeyLoader.loadPrivateKey("serverPrivateKey.der");
        X509Certificate serverCert = KeyLoader.loadCertificate("CASignedServerCertificate.pem");

        BigInteger g = BigInteger.valueOf(2);
        BigInteger N = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
            "FFFFFFFFFFFFFFFF", 16);

        BigInteger serverDHPrivate = CryptoUtils.generatePrivateDH(N);
        BigInteger serverDHPublic = CryptoUtils.computePublicDH(g, serverDHPrivate, N);

        Signature rsaSignature = Signature.getInstance("SHA256withRSA");
        rsaSignature.initSign(serverPrivateKey);
        rsaSignature.update(serverDHPublic.toByteArray());
        byte[] signedDHPub = rsaSignature.sign();

        out.writeObject(serverCert);
        out.writeObject(serverDHPublic);
        out.writeObject(signedDHPub);
        out.flush();

        System.out.println("[Handshake] Sent certificate, DH public key, and signature.");

        X509Certificate clientCert = (X509Certificate) in.readObject();
        BigInteger clientDHPublic = (BigInteger) in.readObject();
        byte[] signedClientDHPub = (byte[]) in.readObject();

        System.out.println("[Handshake] Received client certificate and DH public key. Verifying...");

        X509Certificate caCert = KeyLoader.loadCertificate("CAcertificate.pem");
        clientCert.verify(caCert.getPublicKey());
        System.out.println("[Handshake] Client certificate verified.");

        Signature clientVerify = Signature.getInstance("SHA256withRSA");
        clientVerify.initVerify(clientCert.getPublicKey());
        clientVerify.update(clientDHPublic.toByteArray());

        if (!clientVerify.verify(signedClientDHPub)) {
            throw new SecurityException("Client DH public key signature is invalid");
        }

        System.out.println("[Handshake] Client DH signature verified.");

        BigInteger sharedSecret = CryptoUtils.computeSharedSecret(clientDHPublic, serverDHPrivate, N);
        HandshakeSession session = new HandshakeSession();
        session.clientNonce = clientNonce;
        session.sharedSecret = sharedSecret;
        session.deriveKeys();

        System.out.println("[Handshake] Server handshake complete.");
        return session;
    }

    public static HandshakeSession performClientHandshake(ObjectInputStream in, ObjectOutputStream out) throws Exception 
    {
        System.out.println("[Handshake] Generating client nonce and DH keys...");

        SecureRandom random = new SecureRandom();
        byte[] clientNonce = new byte[32];
        random.nextBytes(clientNonce);

        out.writeObject(clientNonce);
        out.flush();

        BigInteger g = BigInteger.valueOf(2);
        BigInteger N = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
            "FFFFFFFFFFFFFFFF", 16);

        BigInteger clientDHPrivate = CryptoUtils.generatePrivateDH(N);
        BigInteger clientDHPublic = CryptoUtils.computePublicDH(g, clientDHPrivate, N);

        System.out.println("[Handshake] Sent nonce. Receiving server cert and DH key...");

        X509Certificate serverCert = (X509Certificate) in.readObject();
        BigInteger serverDhPublic = (BigInteger) in.readObject();
        byte[] signedDHPub = (byte[]) in.readObject();

        System.out.println("[Handshake] Validating server certificate...");

        X509Certificate caCert = KeyLoader.loadCertificate("CAcertificate.pem");
        serverCert.verify(caCert.getPublicKey());
        System.out.println("[Handshake] Server certificate verified");

        Signature rsaVerify = Signature.getInstance("SHA256withRSA");
        rsaVerify.initVerify(serverCert.getPublicKey());
        rsaVerify.update(serverDhPublic.toByteArray());

        if (!rsaVerify.verify(signedDHPub)) {
            throw new SecurityException("Server DH public key signature is invalid");
        }

        System.out.println("[Handshake] Server DH public key signature verified.");

        PrivateKey clientPrivateKey = KeyLoader.loadPrivateKey("clientPrivateKey.der");
        X509Certificate clientCert = KeyLoader.loadCertificate("CASignedClientCertificate.pem");

        Signature clientSig = Signature.getInstance("SHA256withRSA");
        clientSig.initSign(clientPrivateKey);
        clientSig.update(clientDHPublic.toByteArray());
        byte[] signedClientDHPub = clientSig.sign();

        out.writeObject(clientCert);
        out.writeObject(clientDHPublic);
        out.writeObject(signedClientDHPub);
        out.flush();

        System.out.println("[Handshake] Sent client certificate, DH public key, and signature.");

        BigInteger sharedSecret = CryptoUtils.computeSharedSecret(serverDhPublic, clientDHPrivate, N);
        HandshakeSession session = new HandshakeSession();
        session.clientNonce = clientNonce;
        session.sharedSecret = sharedSecret;
        session.deriveKeys();

        System.out.println("[Handshake] Client handshake complete.");
        return session;
    }
}