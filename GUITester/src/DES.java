import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class DES {

            private KeyGenerator keygenerator = KeyGenerator.getInstance("DES");
            private SecretKey DESKeyGlobal;
            private Cipher desCipher;
            private byte[] textEncrypted;

    public DES() throws NoSuchAlgorithmException {
    }

    public String getDESKeyGlobal() {
        byte[] DESKeyGlobalByte = DESKeyGlobal.getEncoded();
        return bytesToHex(DESKeyGlobalByte);
    }

    public byte[] cypherDES(String message) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {

                SecretKey myDesKey = keygenerator.generateKey();
                DESKeyGlobal = myDesKey;
                desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
                desCipher.init(Cipher.ENCRYPT_MODE,DESKeyGlobal);
                byte[] text = message.getBytes();
                byte[] textEncrypted = desCipher.doFinal(text);
                this.textEncrypted=textEncrypted;
                return textEncrypted;
    }

    public String decryptDES() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        desCipher.init(Cipher.DECRYPT_MODE, DESKeyGlobal);
        byte[] textDecrypted = desCipher.doFinal(textEncrypted);
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

