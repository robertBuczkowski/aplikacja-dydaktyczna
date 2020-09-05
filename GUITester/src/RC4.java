
import org.jetbrains.annotations.NotNull;

import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


public class RC4 {
    KeyGenerator rc4KeyGenerator = KeyGenerator.getInstance("ARCFOUR");
    static byte[] cipherRC4;
    Cipher rc4 = Cipher.getInstance("ARCFOUR");

    SecretKey secretGlobalRc4;

    public String getSecretKey() {
        byte [] secretPrint = secretGlobalRc4.getEncoded();
        return bytesToHex(secretPrint);
    }

    public RC4() throws NoSuchAlgorithmException, NoSuchPaddingException {
    }

    String encrypt(@NotNull String message) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        SecretKey secretKey = rc4KeyGenerator.generateKey();
        rc4.init(Cipher.ENCRYPT_MODE, secretKey);
        secretGlobalRc4 = secretKey;
        byte[] plaintextBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertextBytes = rc4.doFinal(plaintextBytes);
        cipherRC4=ciphertextBytes;
        return bytesToHex(ciphertextBytes);
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }


}