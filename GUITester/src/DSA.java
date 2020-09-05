
import java.math.BigInteger;
import java.security.*;



public class DSA  {

    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA");
    String privateKey;
    String publicKey;
    private PrivateKey privGlobal;
    private PublicKey pubGlobal;
    private Signature signGlobal;
    byte[] signatureGlobal;

    public DSA() throws NoSuchAlgorithmException {
    }

    public void generateKeys() {
        KeyPair pair = keyPairGen.generateKeyPair();
        keyPairGen.initialize(2048);
        PrivateKey privKey = pair.getPrivate();
        PublicKey pubKey = pair.getPublic();

        byte[] privKeyBytes = privKey.getEncoded();
        byte[] pubKeyBytes = pubKey.getEncoded();

        privateKey = bytesToString(privKeyBytes);
        publicKey = bytesToString(pubKeyBytes);

        privGlobal = privKey;
        pubGlobal = pubKey;


    }


    public String signature(String message) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Signature sign = Signature.getInstance("SHA256withDSA");
        sign.initSign(privGlobal);
        byte[] bytes = message.getBytes();
        sign.update(bytes);
        byte[] signature = sign.sign();
        sign.initVerify(pubGlobal);
        sign.update(bytes);
        signGlobal = sign;
        signatureGlobal = signature;
        return bytesToString(signature);
    }


    public String verify() throws SignatureException {
        boolean bool = signGlobal.verify(signatureGlobal);
        String verification = null;
        if (bool) {
            verification = "Weryfikacja podpisu prawidłowa";
        } else {
            verification = "Błędna weryfikacja";
        }
        return verification;
    }
    public String bytesToString(byte[] b) {
        byte[] b2 = new byte[b.length + 1];
        b2[0] = 1;
        System.arraycopy(b, 0, b2, 1, b.length);
        return new BigInteger(b2).toString(36);
    }

}





