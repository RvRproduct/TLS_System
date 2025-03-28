
import java.math.BigInteger;

public class HandshakeSession 
{
    public byte[] clientNonce;
    public BigInteger sharedSecret;

    public byte[] serverEncryptKey;
    public byte[] clientEncryptKey;
    public byte[] serverMACKey;
    public byte[] clientMACKey;
    public byte[] serverIV;
    public byte[] clientIV;

    public void deriveKeys() throws Exception
    {
        byte[] prk = CryptoUtils.hmac(clientNonce, sharedSecret.toByteArray());
        serverEncryptKey = CryptoUtils.hkdfExpand(prk, "server encrypt");
        clientEncryptKey = CryptoUtils.hkdfExpand(serverEncryptKey, "client encrypt");
        serverMACKey = CryptoUtils.hkdfExpand(clientEncryptKey, "server MAC");
        clientMACKey = CryptoUtils.hkdfExpand(serverMACKey, "client MAC");
        serverIV = CryptoUtils.hkdfExpand(clientMACKey, "server IV");
        clientIV = CryptoUtils.hkdfExpand(serverIV, "client IV");
    }
}
