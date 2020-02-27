package se.kyh;

public class Main {
    public static void main(String[] args) {
        KYH_Crypto crypto = new KYH_Crypto();
        //crypto.encrypt("Hej hej på dig dig", "MyNewPubKey.rsa", "crypto");
        //RSA rsa = new RSA(2048);
        //rsa.savePrivateKey("MyNewPrivKey.rsa");
        //rsa.savePublicKey("MyNewPubKey.rsa");
        crypto.decrypt("plaintext.txt", "MyNewPrivKey.rsa", "crypto");
    }
}