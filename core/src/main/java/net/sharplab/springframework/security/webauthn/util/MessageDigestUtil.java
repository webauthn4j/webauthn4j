package net.sharplab.springframework.security.webauthn.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * A Utility class for MessageDigest
 */
public class MessageDigestUtil {



    private MessageDigestUtil(){}

    public static MessageDigest createMessageDigest(String hashAlgorithm) {
        try {
            switch (hashAlgorithm) {
                case "S256":
                    return MessageDigest.getInstance("SHA-256");
                case "S384":
                    return MessageDigest.getInstance("SHA-384");
                case "S512":
                    return MessageDigest.getInstance("SHA-512");
                default:
                    return MessageDigest.getInstance(hashAlgorithm);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

}
