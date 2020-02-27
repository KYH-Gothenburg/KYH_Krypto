package se.kyh;

import se.arthead.RsaKeyPair;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;
import se.arthead.RsaKeyPair;


public class RSA {
    private BigInteger n, d, e;

    private int bitLength = 2048;

    public RSA() {
        e = BigInteger.ZERO;
        d = BigInteger.ZERO;
        n = BigInteger.ZERO;
    }

    public RSA(int bits) {
        bitLength = bits;
        generateKeys();
    }

    public RSA(String pubFileName, String privFileName) {
        readPublicKey(pubFileName);
        readPrivateKey(privFileName);
    }

    public RSA(BigInteger newN, BigInteger newE) {
        setN(newN);
        e = newE;
    }

    private synchronized void generateKeys() {
        SecureRandom rand = new SecureRandom();

        BigInteger p = new BigInteger(bitLength / 2, 100, rand);
        BigInteger q = new BigInteger(bitLength / 2, 100, rand);

        setN(p.multiply(q));
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        e = new BigInteger("3");
        while (phi.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
        setD(e.modInverse(phi));
    }

    public BigInteger getD() {
        return d;
    }

    public void setD(BigInteger d) {
        this.d = d;
    }

    public BigInteger getE() {
        return e;
    }

    public void setE(BigInteger e) {
        this.e = e;
    }

    public BigInteger getN() {
        return n;
    }

    public void setN(BigInteger n) {
        this.n = n;
    }

    public synchronized void encrypt(String message, String fileName) {
        String encrypted = (new BigInteger(message.getBytes())).modPow(e, n).toString();
        try {
            Files.write(Paths.get(fileName), encrypted.getBytes());
        } catch (IOException e1) {
            e1.printStackTrace();
        }
    }

    public synchronized void encrypt(BigInteger message, String fileName) {
        String encrypted = message.modPow(e, n).toString();
        try {
            Files.write(Paths.get(fileName), encrypted.getBytes());
        } catch (IOException e1) {
            e1.printStackTrace();
        }
    }

    public synchronized String decrypt(String fileName) {
        /*
         * BigInteger bigOne = new BigInteger(message); BigInteger bigTwo =
         * bigOne.modPow(d, n); String result = new String(bigTwo.toByteArray()); return
         * result;
         */

        byte[] cipherInput;
        try {
            cipherInput = Files.readAllBytes(Paths.get(fileName));
            String message = new String(cipherInput, StandardCharsets.UTF_8);
            return new String((new BigInteger(message)).modPow(d, n).toByteArray());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public synchronized SecretKeySpec decryptToKeySpec(String fileName) {
        /*
         * BigInteger bigOne = new BigInteger(message); BigInteger bigTwo =
         * bigOne.modPow(d, n); String result = new String(bigTwo.toByteArray()); return
         * result;
         */

        byte[] cipherInput;
        try {
            cipherInput = Files.readAllBytes(Paths.get(fileName));
            String message = new String(cipherInput, StandardCharsets.UTF_8);
            return new SecretKeySpec((new BigInteger(message)).modPow(d, n).toByteArray(), "AES");
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public synchronized void savePublicKey(String fileName) {
        RsaKeyPair publicKey = new RsaKeyPair(e, n);
        try {
            FileOutputStream fileOut = new FileOutputStream(fileName);
            ObjectOutputStream out = new ObjectOutputStream(fileOut);

            out.writeObject(publicKey);
            out.close();
            fileOut.close();
            System.out.println("Saved public key to file " + fileName);
        } catch (IOException i) {
            i.printStackTrace();
        }
    }

    public synchronized void readPublicKey(String fileName) {
        try {
            FileInputStream fileIn = new FileInputStream(fileName);
            ObjectInputStream in = new ObjectInputStream(fileIn);
            RsaKeyPair publicKey = (RsaKeyPair) in.readObject();
            e = publicKey.getKey();
            n = publicKey.getN();
            in.close();
            fileIn.close();
        } catch (IOException i) {
            i.printStackTrace();
        } catch (ClassNotFoundException c) {
            c.printStackTrace();
        }
    }

    public synchronized void savePrivateKey(String fileName) {
        RsaKeyPair privateKey = new RsaKeyPair(d, n);
        try {
            FileOutputStream fileOut = new FileOutputStream(fileName);
            ObjectOutputStream out = new ObjectOutputStream(fileOut);

            out.writeObject(privateKey);
            out.close();
            fileOut.close();
            System.out.println("Saved private key to file " + fileName);
        } catch (IOException i) {
            i.printStackTrace();
        }
    }

    public synchronized void readPrivateKey(String fileName) {
        try {
            FileInputStream fileIn = new FileInputStream(fileName);
            ObjectInputStream in = new ObjectInputStream(fileIn);
            RsaKeyPair privateKey = (RsaKeyPair) in.readObject();
            d = privateKey.getKey();
            n = privateKey.getN();
            in.close();
            fileIn.close();
        } catch (IOException i) {
            i.printStackTrace();
        } catch (ClassNotFoundException c) {
            c.printStackTrace();
        }
    }

}