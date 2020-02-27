package se.kyh;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class KYH_Crypto {

    public KYH_Crypto() {

    }

    public void encrypt(String message, String publicKeyFileName, String cryptoFileName) {
        AES aes = new AES();
        IvParameterSpec iv = aes.generateIV();
        aes.saveIv(cryptoFileName + ".iv", iv);
        SecretKeySpec aesKey = aes.generateKey();

        aes.encrypt(message, cryptoFileName + ".aes", aesKey, iv);
        RSA rsa = new RSA();
        rsa.readPublicKey(publicKeyFileName);
        rsa.encrypt(new BigInteger(aesKey.getEncoded()), cryptoFileName + ".rsa");
    }

    public void decrypt(String outPutFileName, String RsaPrivKey, String cryptoFileName) {
        RSA rsa = new RSA();
        rsa.readPrivateKey(RsaPrivKey);
        SecretKeySpec aesKey = rsa.decryptToKeySpec(cryptoFileName + ".rsa");

        AES aes = new AES();
        IvParameterSpec iv = aes.readIv(cryptoFileName + ".iv");
        String plaintext = aes.decrypt(cryptoFileName + ".aes", aesKey, iv);

        Path path = Paths.get(outPutFileName);
        try (BufferedWriter writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            writer.write(plaintext);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
}
