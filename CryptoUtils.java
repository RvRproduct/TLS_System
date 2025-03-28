import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

public class CryptoUtils 
{
    public static final String HMAC_ALGORITHM = "HmacSHA256";
    public static final int AES_KEY_SIZE = 16;
    public static final int HMAC_SIZE = 32;

    public static byte[] hkdfExpand(byte[] inputKey, String tag) throws Exception
    {
        Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(inputKey, HMAC_ALGORITHM);
        hmac.init(keySpec);

        byte[] tagBytes = tag.getBytes("UTF-8");
        byte[] input = Arrays.copyOf(tagBytes, tagBytes.length + 1);
        // We should Append byte with value 1
        input[input.length - 1] = 0x01;

        byte[] okm = hmac.doFinal(input);
        return Arrays.copyOf(okm, AES_KEY_SIZE);
    }

    public static byte[] hmac(byte[] key, byte[] data) throws Exception
    {
        Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
        hmac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
        return hmac.doFinal(data);
    }

    public static byte[] aesEncrypt(byte[] key, byte[] iv, byte[] plaintext) throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(plaintext);
    }

    public static byte[] aesDecrypt(byte[] key, byte[] iv, byte[] ciphertext) throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(ciphertext);
    }

    public static BigInteger generatePrivateDH(BigInteger N)
    {
        SecureRandom rand = new SecureRandom();
        return new BigInteger(N.bitLength() - 1, rand);
    }

    public static BigInteger computePublicDH(BigInteger g, BigInteger privateKey, BigInteger N)
    {
        return g.modPow(privateKey, N);
    }

    public static BigInteger computeSharedSecret(BigInteger receivedPublic, BigInteger privateKey, BigInteger N)
    {
        return receivedPublic.modPow(privateKey, N);
    }
}
