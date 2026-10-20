package com.example.app;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class SessionLoader {
    public Object loadSession(byte[] cookie) throws IOException, ClassNotFoundException {
        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(cookie)); // expect: DESER
        return in.readObject();
    }

    public Document parseConfig(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance(); // expect: XXE
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xml.getBytes()));
    }

    /*
     * Old implementation kept for reference; commented-out code should not be reported:
     * String q = "SELECT * FROM sessions WHERE id = " + id;
     */
    public String describe() {
        return "session loader";
    }
}
