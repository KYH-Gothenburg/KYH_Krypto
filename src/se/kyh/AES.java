package se.kyh;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class AES {
    public IvParameterSpec generateIV() {
        byte[] iv = new byte[128 / 8];
        SecureRandom srandom = new SecureRandom();
        srandom.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public void saveIv(String ivFileName, IvParameterSpec iv) {
        try {
            FileOutputStream out = new FileOutputStream(ivFileName);
            out.write(iv.getIV());
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public IvParameterSpec readIv(String ivFileName)  {
        byte[] iv = new byte[0];
        try {
            iv = Files.readAllBytes(Paths.get(ivFileName));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new IvParameterSpec(iv);
    }

    public SecretKeySpec generateKey() {
        try {
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            return new SecretKeySpec(keygen.generateKey().getEncoded(), "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public SecretKeySpec keyFromPassPhrase(String passPhrase) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = new String("12345678").getBytes();
        int iterationCount = 1024;
        int keyStrength = 256;
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(passPhrase.toCharArray(), salt, iterationCount, keyStrength);
        SecretKey key = factory.generateSecret(spec);
        return new SecretKeySpec(key.getEncoded(), "AES");
    }

    public void encrypt(String plainText, String outFile, SecretKeySpec skey, IvParameterSpec iv) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skey, iv);

            FileOutputStream out = new FileOutputStream(outFile);
            byte[] input = plainText.getBytes(StandardCharsets.UTF_8);
            byte[] cipherOutput = cipher.doFinal(input);
            out.write(cipherOutput);
            out.close();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
                | IOException e) {
            e.printStackTrace();
        }
    }

    public String decrypt(String inFile, SecretKeySpec skey, IvParameterSpec iv)
    {
         Cipher cipher = null;
         try {
             cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
             cipher.init(Cipher.DECRYPT_MODE, skey, iv);
             byte[] cipherInput = Files.readAllBytes(Paths.get(inFile));
             return new String(cipher.doFinal(cipherInput), StandardCharsets.UTF_8);
         } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IOException | IllegalBlockSizeException | BadPaddingException e) {
             e.printStackTrace();
         }
         return null;
      }
}
