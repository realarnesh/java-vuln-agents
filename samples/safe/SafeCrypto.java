package com.example.app;

import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilderFactory;

public class SafeCrypto {
    private final SecureRandom random = new SecureRandom();

    public byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    public Cipher cipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    public DocumentBuilderFactory xmlFactory() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return factory;
    }

    public String token() {
        return Long.toHexString(random.nextLong());
    }
}
