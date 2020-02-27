package se.arthead;

import java.math.BigInteger;

public class RsaKeyPair implements java.io.Serializable {
    private static final long serialVersionUID = 4L;
    private BigInteger key;
    private BigInteger n;

    public RsaKeyPair(BigInteger key, BigInteger n) {
        this.setKey(key);
        this.setN(n);
    }

    public BigInteger getN() {
        return n;
    }

    public void setN(BigInteger n) {
        this.n = n;
    }

    public BigInteger getKey() {
        return key;
    }

    public void setKey(BigInteger key) {
        this.key = key;
    }
}