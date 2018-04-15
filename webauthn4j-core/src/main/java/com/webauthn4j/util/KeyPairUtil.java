package com.webauthn4j.util;

import com.webauthn4j.exception.UnexpectedCheckedException;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class KeyPairUtil {

    private KeyPairUtil(){}

    public static KeyPairGenerator createKeyPairGenerator(){
        try {
            return KeyPairGenerator.getInstance("ECDSA");
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static KeyPair createKeyPair(byte[] seed){
        KeyPairGenerator keyPairGenerator = createKeyPairGenerator();
        SecureRandom random = new SecureRandom();
        if(seed!=null){
            random.setSeed(seed);
        }
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "SunEC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
            keyPairGenerator.initialize(ecParameterSpec, random);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidParameterSpecException | InvalidAlgorithmParameterException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static KeyPair createKeyPair(){
        return createKeyPair(null);
    }
}
