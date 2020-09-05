import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Objects;

public class aplikacjaDydaktyczna extends JFrame {
    private JTabbedPane tabbedPane1;
    private JPanel panel1;
    private JTabbedPane tabbedPaneRSA;
    private JTabbedPane tabbedPaneAES;
    private JTabbedPane tabbedPaneDES;
    private JTabbedPane tabbedPaneRC4;
    private JTabbedPane tabbedPanePodst;
    private JTabbedPane tabbedPaneDSA;
    private JTextArea RC4Jawny;
    private JTextArea RC4Klucz;
    private JTextArea RC4Szyfr;
    private JButton RC4Szyfruj;
    private JButton RC4Wyczysc;
    private JButton RC4Deszyfruj;
    private JTextArea textJawny;
    private JTextArea zaszyfrowane;
    private JButton szyfrujButton1;
    private JButton buttonWyczyscRSA;
    private JButton deszyfrujButton1;
    private JTextArea kluczPublicznyText;
    private JTextArea kluczPrywatnyText;
    private JTextArea CezarJawny;
    private JTextArea cezarSzyfr;
    private JButton szyfrujButton;
    private JButton wyczyśćButtonCezar;
    private JButton deszyfrujButton;
    private JTextArea vigenereKlucz;
    private JTextArea vigenereJawny;
    private JTextArea vigenereSzyfr;
    private JButton deszyfrujVigenere;
    private JButton wyczyśćVigenere;
    private JButton szyfrujVigenere;
    private JTextArea DHp;
    private JTextArea DHg;
    private JTextArea privAlice;
    private JTextArea privBob;
    private JTextArea msgAlice;
    private JTextArea msgBob;
    private JTextArea keyAlice;
    private JTextArea keyBob;
    private JButton generujWartościPIButton;
    private JButton generujWiadomościButton;
    private JButton wyczyśćButton;
    private JButton obliczOdebraneKluczeButton;
    private JTextArea textDesJawny;
    private JTextArea textDesKlucz;
    private JTextArea textDesSzyfr;
    private JButton szyfrujButtonDES;
    private JButton wyczyśćButtonDES;
    private JButton deszyfrujButtonDES;
    private JTextArea jawnyAES;
    private JTextArea kluczAES;
    private JTextArea szyfrogramAES;
    private JButton szyfrujButtonAES;
    private JButton wyczyśćButtonAES;
    private JButton deszyfrujButtonAES;
    private JComboBox dlugoscKluczaCombo;
    private JTextArea statusDSA;
    private JTextArea teksJawnyDSA;
    private JTextArea podpisaneDSA;
    private JTextArea kluczPublicznyDSA;
    private JTextArea kluczPrywatnyDSA;
    private JButton podpiszButton;
    private JButton wyczyśćButton1;
    private JButton weryfikujPodpisButton;
    private JTextArea przesuniecieCezar;

    private aplikacjaDydaktyczna(String title) throws NoSuchAlgorithmException, NoSuchPaddingException {
        super(title);
        this.setDefaultCloseOperation(EXIT_ON_CLOSE);
        this.setContentPane(panel1);
        this.pack();
        RC4 rc4Helper = new RC4();
        DiffieHellman DHHelper = new DiffieHellman();
        DES desHelper = new DES();
        AES aesHelper = new AES();
        RSA RSATester = new RSA();
        DSA DSAHelper = new DSA();


        RC4Szyfruj.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {
                    RC4Szyfr.setText(rc4Helper.encrypt(RC4Jawny.getText()));
                } catch (InvalidKeyException | IllegalBlockSizeException | UnsupportedEncodingException | BadPaddingException e) {
                    e.printStackTrace();
                }
                RC4Klucz.setText(rc4Helper.getSecretKey());

            }
        });
        RC4Wyczysc.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                RC4Klucz.setText("");
                RC4Jawny.setText("");
                RC4Szyfr.setText("");
            }
        });
        szyfrujButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {


                if (!StringValidation.validtaeString(CezarJawny.getText()))
                    JOptionPane.showMessageDialog(panel1, "W tekście jawnym pojawiły się niedozwolone znaki, usuń je i spróbuj ponownie.");
                else if ((Integer.parseInt(przesuniecieCezar.getText()) < 0) | (Integer.parseInt(przesuniecieCezar.getText()) > 26))
                    JOptionPane.showMessageDialog(panel1, "Wartośc przesunięcia powinna się mieścić w przedziale 0-26");
                else
                    cezarSzyfr.setText(szyfrCezara.encryptCezar(CezarJawny.getText(), Integer.parseInt(przesuniecieCezar.getText())));
            }catch (NumberFormatException e){
                    JOptionPane.showMessageDialog(panel1, "Podano nieprawidłowe dane, spróbuj ponownie.");
                }
        }
        });
        deszyfrujButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                if(!StringValidation.validtaeString(cezarSzyfr.getText()))
                    JOptionPane.showMessageDialog(panel1, "W szyfrogramie pojawiły się niedozwolone znaki, usuń je i spróbuj ponownie.");
                else if ((Integer.parseInt(przesuniecieCezar.getText()) < 0) | (Integer.parseInt(przesuniecieCezar.getText()) > 26))
                JOptionPane.showMessageDialog(panel1, "Wartośc przesunięcia powinna się mieścić w przedziale 0-26");
                else
                CezarJawny.setText(szyfrCezara.decryptCeazar(cezarSzyfr.getText(), Integer.parseInt(przesuniecieCezar.getText())));
            }
        });
        wyczyśćButtonCezar.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                cezarSzyfr.setText("");
                CezarJawny.setText("");
                przesuniecieCezar.setText("");
            }
        });
        szyfrujVigenere.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {

                if(!StringValidation.validtaeString(vigenereKlucz.getText()))
                    JOptionPane.showMessageDialog(panel1, "W kluczu pojawiły się niedozwoolone znaki, usuń je i spróbuj ponownie.");
                else if(!StringValidation.validtaeString(vigenereJawny.getText()))
                    JOptionPane.showMessageDialog(panel1, "W tekście jawnym pojawiły się niedozwolone znaki, usuń je i spróbuj ponownie.");
                else {
                    try {
                            vigenereKlucz.setText(vigenere.generateKey(vigenereJawny.getText().toUpperCase(), vigenereKlucz.getText().toUpperCase()));
                            vigenereKlucz.setEditable(false);
                            vigenereSzyfr.setText(vigenere.cipherText(vigenereJawny.getText().toUpperCase(), vigenereKlucz.getText().toUpperCase()));
                    }catch (StringIndexOutOfBoundsException e){
                        JOptionPane.showMessageDialog(panel1, "Aby zaszyfrować wiadomość musisz podać tekst jawny i klucz. Spróbuj ponownie");
                    }catch(OutOfMemoryError x){
                        JOptionPane.showMessageDialog(panel1, "Klucz nie może być dłuższy od tekstu jawnego, spróbuj ponownie");
                    }
                }
            }
        });
        deszyfrujVigenere.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                if (!StringValidation.validtaeString(vigenereKlucz.getText()))
                    JOptionPane.showMessageDialog(panel1, "W kluczu pojawiły się niedozwolone znaki, usuń je i spróbuj ponownie.");
                else if (!StringValidation.validtaeString(vigenereSzyfr.getText()))
                    JOptionPane.showMessageDialog(panel1, "W tekście jawnym pojawiły się niedozwolone znaki, usuń je i spróbuj ponownie.");
                else {
                    try{
                    vigenereKlucz.setText(vigenere.generateKey(vigenereSzyfr.getText().toUpperCase(), vigenereKlucz.getText().toUpperCase()));
                    vigenereJawny.setText(vigenere.originalText(vigenereSzyfr.getText().toUpperCase(), vigenereKlucz.getText().toUpperCase()));
                }catch (StringIndexOutOfBoundsException e){
                        JOptionPane.showMessageDialog(panel1, "Aby deszyfrować wiadomość musisz podać szyfrogram i klucz. Spróbuj ponownie");
                    }catch(OutOfMemoryError x){
                        JOptionPane.showMessageDialog(panel1, "Klucz nie może być dłuższy od szyfrogramu, spróbuj ponownie");
                    }
                }
            }
        });
        wyczyśćVigenere.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                vigenereJawny.setText("");
                vigenereKlucz.setEditable(true);
                vigenereKlucz.setText("");
                vigenereSzyfr.setText("");
            }
        });
        generujWartościPIButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                DHHelper.genPrimeAndPrimitiveRoot();
                DHg.setText((DHHelper.getG().toString()));
                DHp.setText(DHHelper.getP().toString());
            }
        });
        generujWiadomościButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
               try{
                msgAlice.setText(DHHelper.getAliceMessage(BigInteger.valueOf(Long.parseLong(privAlice.getText()))).toString());
                msgBob.setText(DHHelper.getBobMessage(BigInteger.valueOf(Long.parseLong(privBob.getText()))).toString());
            } catch (NumberFormatException e) {

                   JOptionPane.showMessageDialog(panel1,"Wygeneruj wartości p i g, podaj też poprawne wartości kluczy prywatnych(liczba).");
               }
            }
    });
        obliczOdebraneKluczeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
               try {


                keyAlice.setText(DHHelper.aliceCalculationOfKey(BigInteger.valueOf(Long.parseLong(msgBob.getText())), BigInteger.valueOf(Long.parseLong(privAlice.getText()))).toString());
                keyBob.setText(DHHelper.bobCalculationOfKey(BigInteger.valueOf(Long.parseLong(msgAlice.getText())), BigInteger.valueOf(Long.parseLong(privBob.getText()))).toString());
            }catch (NumberFormatException e){
                   JOptionPane.showMessageDialog(panel1,"Wygeneruj wiadomości wysyłane przez Alice i Boba.");
               }
            }
        });
        wyczyśćButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                keyAlice.setText("");
                keyBob.setText("");
                msgBob.setText("");
                msgAlice.setText("");
                DHp.setText("");
                DHg.setText("");
                privAlice.setText("");
                privBob.setText("");
            }
        });
        szyfrujButtonDES.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {
                    textDesSzyfr.setText(DES.bytesToHex(desHelper.cypherDES(textDesJawny.getText())));
                    textDesKlucz.setText(desHelper.getDESKeyGlobal());
                } catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException e) {
                    e.printStackTrace();
                }
            }
        });
        deszyfrujButtonDES.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {
                    textDesJawny.setText(desHelper.decryptDES());
                } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                    e.printStackTrace();
                }catch (NullPointerException x){
                    JOptionPane.showMessageDialog(panel1, "Najpierw zaszyfruj wiadomość aby móc ją odszyfrować.");
                }
            }
        });
        wyczyśćButtonDES.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                textDesJawny.setText("");
                textDesSzyfr.setText("");
                textDesKlucz.setText("");
            }
        });
        szyfrujButtonAES.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {
                    szyfrogramAES.setText(aesHelper.cypherAES(jawnyAES.getText(), Integer.parseInt(Objects.requireNonNull(dlugoscKluczaCombo.getSelectedItem()).toString())));
                    kluczAES.setText(aesHelper.getAESKeyGlobal());
                } catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException e) {
                    e.printStackTrace();
                }
            }
        });
        deszyfrujButtonAES.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {
                    jawnyAES.setText(aesHelper.decryptAES());
                } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | NullPointerException e) {
                    JOptionPane.showMessageDialog(panel1, "Wstaw poprawne dane.");
                }
            }
        });
        wyczyśćButtonAES.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                jawnyAES.setText("");
                kluczAES.setText("");
                szyfrogramAES.setText("");
            }
        });


        deszyfrujButton1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {
                    textJawny.setText(RSATester.Decrypt(zaszyfrowane.getText()));
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                   JOptionPane.showMessageDialog(panel1, "Zmodykikowano szyfrogram lub parę kluczy szyfrujących.");
                } catch (NumberFormatException x) {
                    JOptionPane.showMessageDialog(panel1, "Aby deszyfrować wiadomość najpierw musisz ją zaszyfrować.");
                }
            }
        });


        buttonWyczyscRSA.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                textJawny.setText("");
                zaszyfrowane.setText("");
                kluczPublicznyText.setText("");
                kluczPrywatnyText.setText("");
                JOptionPane.showMessageDialog(panel1, "Pola zostały wyczyszczone");
            }
        });


        szyfrujButton1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {
                    zaszyfrowane.setText(RSATester.Encrypt(textJawny.getText()));
                    kluczPrywatnyText.setText(RSATester.getPrivKeyPrint());
                    kluczPublicznyText.setText(RSATester.getPublicKeyPrint());
                } catch (NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | NoSuchPaddingException e) {
                    e.printStackTrace();
                }catch(IllegalBlockSizeException x){
                    JOptionPane.showMessageDialog(panel1, "Teks jawny jest za długi. Skróć wiadomość i spróbuj jeszcze raz.");
                }
            }
        });
        podpiszButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                DSAHelper.generateKeys();
                kluczPublicznyDSA.setText(DSAHelper.publicKey);
                kluczPrywatnyDSA.setText(DSAHelper.privateKey);
                try {
                    podpisaneDSA.setText(DSAHelper.signature(teksJawnyDSA.getText()));
                } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                    e.printStackTrace();
                }
            }
        });
        weryfikujPodpisButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {
                    statusDSA.setText(DSAHelper.verify());
                } catch (SignatureException e) {
                    e.printStackTrace();
                }catch (NullPointerException e){
                    JOptionPane.showMessageDialog(panel1, "Najpierw musisz podpisać wiadomość żeby ją zweryfikować. Spróbuj ponownie");
                }
            }
        });
        wyczyśćButton1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                    statusDSA.setText("");
                    podpisaneDSA.setText("");
                    kluczPrywatnyDSA.setText("");
                    kluczPublicznyDSA.setText("");
                    teksJawnyDSA.setText("");
            }
        });
    }



        public static void main (String[]args) throws NoSuchAlgorithmException, NoSuchPaddingException {
            JFrame frame = new aplikacjaDydaktyczna("Aplikacja dydaktyczna dla wizualizacji wykonania algorytmów kryptograficznych");
            frame.setVisible(true);
            frame.setSize(1250, 500);
            frame.setResizable(false);
        }
    }

