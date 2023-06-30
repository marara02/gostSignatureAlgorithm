package kz.main;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;

//java -cp encryption-test-1.1.1.jar;kalkancrypt-0.7.2.jar kz.main.Main GOST3411-2015-512 ECGOST3410

public class Main {
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static void main(String[] args) {
        Provider kalkanProvider = new KalkanProvider();

        String filePath = "C:/Users/020925600745/Desktop/req_test.txt";
        String hashAlgorithm = args[0];
        String encryptionAlgorithm = args[1];
        String p12filePath = "C:/Users/020925600745/Documents/keytool-shep/GOSTKNCA_4a37965b1094c0f590fe79b041f503de03214dd8.p12";
        String password = "Aa123456";
        String alias = "4a37965b1094c0f590fe79b041f503de03214dd8";

        boolean exists = false;
        Provider[] providers = Security.getProviders();
        for (Provider p : providers) {
            if (p.getName().equals(kalkanProvider.getName())) {
                exists = true;
            }
        }
        if (!exists) {
            Security.addProvider(kalkanProvider);
        }
        PrivateKey privateKey = getPrivateKey(p12filePath, password, alias);
        PublicKey publicKey = getPublicKey(p12filePath, password, alias);

        byte[] hashedData = messageHash(filePath, hashAlgorithm, kalkanProvider);
        byte[] encryptedHashData = encryptGOST3410(hashedData, encryptionAlgorithm, privateKey, kalkanProvider);

        System.out.println("Hash " + bytesToHex(hashedData));
        System.out.println("Encrypted " + bytesToHex(encryptedHashData));

        boolean isVerified = signVerify(hashedData, kalkanProvider, encryptionAlgorithm, publicKey, encryptedHashData);
        System.out.println("Signature verified - " + isVerified);
    }

    public static byte[] messageHash(String filePath, String hashAlgorithm, Provider kalkanProvider) {
        String text;
        try {
            text = new String(Files.readAllBytes(Paths.get(filePath)));
            MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm, kalkanProvider);
            return messageDigest.digest(text.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalArgumentException("Hashing error ", e);
        }
    }

    public static PublicKey getPublicKey(String file, String pass, String alias) {
        try {
            FileInputStream fileInputStream = new FileInputStream(file);
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(fileInputStream, pass.toCharArray());
            Certificate certificate = keyStore.getCertificate(alias);
            return certificate.getPublicKey();
        } catch (Exception e) {
            throw new SecurityException("Error in public key ", e);
        }
    }

    public static PrivateKey getPrivateKey(String file, String pass, String alias) {
        try {
            FileInputStream fileInputStream = new FileInputStream(file);
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            char[] passwordChars = pass.toCharArray();
            keyStore.load(fileInputStream, passwordChars);

            KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(passwordChars);
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, passwordProtection);

            return privateKeyEntry.getPrivateKey();
        } catch (Exception e) {
            throw new SecurityException("Error in defining private key ", e);
        }
    }

    public static byte[] encryptGOST3410(byte[] data, String encryptionAlgo, PrivateKey privateKey, Provider kalkanProvider) {
        try {
            Signature signature = Signature.getInstance(encryptionAlgo, kalkanProvider);
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception exception) {
            throw new SecurityException("Signing failed ", exception);
        }
    }

    public static boolean signVerify(byte[] messageBytes, Provider kalkanProvider, String encryptionAlgo, PublicKey publicKey, byte[] signedData) {
        try {
            Signature signature = Signature.getInstance(encryptionAlgo, kalkanProvider);
            signature.initVerify(publicKey);
            signature.update(messageBytes);
            return signature.verify(signedData);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new SecurityException("Verification Failed: ", e);
        }
    }

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
