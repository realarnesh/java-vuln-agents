package com.example.app;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import javax.crypto.Cipher;

public class CryptoUtil {
    private String apiKey = "sk_live_51HxExampleKey"; // expect: SECRET

    public byte[] hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5"); // expect: WEAK_HASH
        return md.digest(password.getBytes());
    }

    public byte[] checksum(byte[] data) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-1").digest(data); // expect: WEAK_HASH
    }

    public Cipher legacyCipher() throws Exception {
        return Cipher.getInstance("DES/ECB/PKCS5Padding".substring(0, 3)); // indirect, not detected by design
    }

    public Cipher ecbCipher() throws Exception {
        return Cipher.getInstance("AES"); // expect: WEAK_CIPHER
    }

    public String resetToken() {
        Random random = new Random(); // expect: WEAK_RANDOM
        return Long.toHexString(random.nextLong());
    }
}
