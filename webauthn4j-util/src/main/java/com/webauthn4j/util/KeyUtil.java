package com.webauthn4j.util;

import com.webauthn4j.util.exception.UnexpectedCheckedException;

import java.io.UncheckedIOException;
import java.security.*;
import java.security.spec.*;

public class KeyUtil {

    private KeyUtil(){}

    public static PrivateKey loadECDSAPrivateKey(byte[] bytes){
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedCheckedException(e);
        }
        try {
            return keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
           throw new IllegalArgumentException(e); //TODO
        }
    }

    public static KeyPairGenerator createKeyPairGenerator(){
        try {
            return KeyPairGenerator.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static KeyPair createKeyPair(byte[] seed){
        KeyPairGenerator keyPairGenerator = createKeyPairGenerator();
        SecureRandom random = null;
        try {
            if(seed!=null){
                random = SecureRandom.getInstance("SHA1PRNG"); // to make it deterministic
                random.setSeed(seed);
            }
            else {
                random = SecureRandom.getInstanceStrong();
            }
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
