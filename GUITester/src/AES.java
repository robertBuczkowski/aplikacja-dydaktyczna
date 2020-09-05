import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AES {
    private KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
    private SecretKey AESKeyGlobal;
    private Cipher aesCipher;
    private byte[] textEncrypted;
    SecureRandom secureRandom;

    public String getAESKeyGlobal() {
        byte [] AESKeyGlobalBytes = AESKeyGlobal.getEncoded();
        return bytesToHex(AESKeyGlobalBytes);
    }

    public AES() throws NoSuchAlgorithmException {
    }

    public String cypherAES(String message, int keysize) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {

        secureRandom = SecureRandom.getInstanceStrong();
        keygenerator.init(keysize, secureRandom);
        SecretKey AesKey = keygenerator.generateKey();
        AESKeyGlobal = AesKey;
        aesCipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
        aesCipher.init(Cipher.ENCRYPT_MODE,AESKeyGlobal);
        byte[] text = message.getBytes();
        byte[] textEncrypted = aesCipher.doFinal(text);
        this.textEncrypted=textEncrypted;
        return bytesToHex(textEncrypted);
    }

    public String decryptAES() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        IvParameterSpec iv = new IvParameterSpec(aesCipher.getIV());
        aesCipher.init(Cipher.DECRYPT_MODE, AESKeyGlobal, iv,  secureRandom);
        byte[] textDecrypted = aesCipher.doFinal(textEncrypted);
        return  new String(textDecrypted);

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

