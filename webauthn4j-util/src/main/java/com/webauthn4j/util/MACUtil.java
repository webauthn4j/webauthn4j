package com.webauthn4j.util;

import com.webauthn4j.util.exception.UnexpectedCheckedException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class MACUtil {

    private MACUtil(){}

    public static byte[] calculateHMAC(byte[] message, byte[] secret){
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secret, "HmacSHA256");
            mac.init(secretKeySpec);
            return mac.doFinal(message);

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new UnexpectedCheckedException(e);
        }
    }
}
