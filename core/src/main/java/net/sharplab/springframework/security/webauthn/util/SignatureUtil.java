package net.sharplab.springframework.security.webauthn.util;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;

/**
 * A Utility class for signature
 */
public class SignatureUtil {

    private SignatureUtil(){}

    public static Signature createSignature(String algorithm){
        try {
            return Signature.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e); //TODO
        }
    }
}
