package com.webauthn4j.util;

import com.webauthn4j.util.exception.UnexpectedCheckedException;

import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class KeyUtil {

    private KeyUtil(){}

    public static PrivateKey loadECPrivateKey(byte[] bytes){
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

    public static KeyPairGenerator createECKeyPairGenerator(){
        try {
            return KeyPairGenerator.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static KeyPair createECKeyPair(byte[] seed, ECParameterSpec ecParameterSpec){
        KeyPairGenerator keyPairGenerator = createECKeyPairGenerator();
        SecureRandom random = null;
        try {
            if(seed!=null){
                random = SecureRandom.getInstance("SHA1PRNG"); // to make it deterministic
                random.setSeed(seed);
            }
            else {
                random = SecureRandom.getInstanceStrong();
            }
            keyPairGenerator.initialize(ecParameterSpec, random);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static KeyPair createECKeyPair(byte[] seed) {
        return createECKeyPair(seed, ECUtil.P_256_SPEC);
    }

    public static KeyPair createECKeyPair(ECParameterSpec ecParameterSpec){
        return createECKeyPair(null, ecParameterSpec);
    }

    public static KeyPair createECKeyPair(){
        return createECKeyPair((byte[]) null);
    }
}
