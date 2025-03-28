import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;

public class KeyLoader 
{
    public static PrivateKey loadPrivateKey(String path) throws Exception
    {
        byte[] keyBytes = Files.readAllBytes(Paths.get(path));
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    public static X509Certificate loadCertificate(String path) throws Exception
    {
        try (InputStream in = new FileInputStream(path))
        {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(in);
        }
    }

    public static PublicKey extractPublicKeyFromCert(X509Certificate cert)
    {
        return cert.getPublicKey();
    }
}
