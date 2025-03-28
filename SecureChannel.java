import java.io.*;

public class SecureChannel 
{
    public enum Role
    {
        CLIENT, SERVER
    }

    private final HandshakeSession session;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final Role role;

    public SecureChannel(HandshakeSession session, ObjectInputStream in, ObjectOutputStream out, Role role)
    {
        this.session = session;
        this.in = in;
        this.out = out;
        this.role = role;
    }

    public void send(byte[] plaintext) throws Exception {
        byte[] mac = CryptoUtils.hmac(
            role == Role.SERVER ? session.serverMACKey : session.clientMACKey,
            plaintext
        );
        byte[] combined = new byte[plaintext.length + mac.length];
        System.arraycopy(plaintext, 0, combined, 0, plaintext.length);
        System.arraycopy(mac, 0, combined, plaintext.length, mac.length);
    
        byte[] ciphertext = CryptoUtils.aesEncrypt(
            role == Role.SERVER ? session.serverEncryptKey : session.clientEncryptKey,
            role == Role.SERVER ? session.serverIV : session.clientIV,
            combined
        );
        out.writeObject(ciphertext);
        out.flush();
    }
    
    public byte[] receive() throws Exception {
        byte[] ciphertext = (byte[]) in.readObject();
        byte[] combined = CryptoUtils.aesDecrypt(
            role == Role.SERVER ? session.clientEncryptKey : session.serverEncryptKey,
            role == Role.SERVER ? session.clientIV : session.serverIV,
            ciphertext
        );
    
        int messageLen = combined.length - CryptoUtils.HMAC_SIZE;
        byte[] message = new byte[messageLen];
        byte[] receivedMac = new byte[CryptoUtils.HMAC_SIZE];
    
        System.arraycopy(combined, 0, message, 0, messageLen);
        System.arraycopy(combined, messageLen, receivedMac, 0, CryptoUtils.HMAC_SIZE);
    
        byte[] computedMac = CryptoUtils.hmac(
            role == Role.SERVER ? session.clientMACKey : session.serverMACKey,
            message
        );
    
        if (!java.util.Arrays.equals(receivedMac, computedMac)) {
            throw new SecurityException("HMAC verification failed");
        }
    
        return message;
    }
}
